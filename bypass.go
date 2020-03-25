package bypass

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	glob "github.com/gobwas/glob"
)

// Bypasser checks if the address addr should be bypassed.
type Bypasser interface {
	Bypass(addr string) bool
}

// Matcher is a generic pattern matcher,
// it gives the match result of the given pattern for specific v.
type Matcher interface {
	Match(v string) bool
	String() string
}

// NewMatcher creates a Matcher for the given pattern.
// The acutal Matcher depends on the pattern:
// IP Matcher if pattern is a valid IP address.
// CIDR Matcher if pattern is a valid CIDR address.
// Domain Matcher if both of the above are not.
func NewMatcher(pattern string) Matcher {
	if pattern == "" {
		return nil
	}
	if ip := net.ParseIP(pattern); ip != nil {
		return IPMatcher(ip)
	}
	if _, inet, err := net.ParseCIDR(pattern); err == nil {
		return CIDRMatcher(inet)
	}
	return DomainMatcher(pattern)
}

type ipMatcher struct {
	ip net.IP
}

// IPMatcher creates a Matcher for a specific IP address.
func IPMatcher(ip net.IP) Matcher {
	return &ipMatcher{
		ip: ip,
	}
}

func (m *ipMatcher) Match(ip string) bool {
	if m == nil {
		return false
	}
	return m.ip.Equal(net.ParseIP(ip))
}

func (m *ipMatcher) String() string {
	return "ip " + m.ip.String()
}

type cidrMatcher struct {
	ipNet *net.IPNet
}

// CIDRMatcher creates a Matcher for a specific CIDR notation IP address.
func CIDRMatcher(inet *net.IPNet) Matcher {
	return &cidrMatcher{
		ipNet: inet,
	}
}

func (m *cidrMatcher) Match(ip string) bool {
	if m == nil || m.ipNet == nil {
		return false
	}
	return m.ipNet.Contains(net.ParseIP(ip))
}

func (m *cidrMatcher) String() string {
	return "cidr " + m.ipNet.String()
}

type domainMatcher struct {
	pattern string
	glob    glob.Glob
}

// DomainMatcher creates a Matcher for a specific domain pattern,
// the pattern can be a plain domain such as 'example.com',
// a wildcard such as '*.exmaple.com' or a special wildcard '.example.com'.
func DomainMatcher(pattern string) Matcher {
	p := pattern
	if strings.HasPrefix(pattern, ".") {
		p = pattern[1:] // trim the prefix '.'
		pattern = "*" + p
	}
	return &domainMatcher{
		pattern: p,
		glob:    glob.MustCompile(pattern),
	}
}

func (m *domainMatcher) Match(domain string) bool {
	if m == nil || m.glob == nil {
		return false
	}

	if domain == m.pattern {
		return true
	}
	return m.glob.Match(domain)
}

func (m *domainMatcher) String() string {
	return "domain " + m.pattern
}

type bypasser struct {
	reversed bool
	matchers []Matcher
	period   time.Duration // the period for live reloading
	stopped  chan struct{}
	mux      sync.RWMutex
}

// NewBypasser creates and initializes a new Bypasser using Matchers as its match rules.
// The rules will be reversed if the reversed is true.
func NewBypasser(reversed bool, matchers ...Matcher) Bypasser {
	return &bypasser{
		matchers: matchers,
		reversed: reversed,
		stopped:  make(chan struct{}),
	}
}

// NewBypasserPatterns creates and initializes a new Bypasser using match patterns as its match rules.
// The rules will be reversed if the reverse is true.
func NewBypasserPatterns(reversed bool, patterns ...string) Bypasser {
	var matchers []Matcher
	for _, pattern := range patterns {
		if m := NewMatcher(pattern); m != nil {
			matchers = append(matchers, m)
		}
	}
	bp := NewBypasser(reversed, matchers...)
	return bp
}

// Bypass reports whether the address addr should be bypassed.
func (bp *bypasser) Bypass(addr string) bool {
	if bp == nil || addr == "" {
		return false
	}

	// try to strip the port
	if host, port, _ := net.SplitHostPort(addr); host != "" && port != "" {
		if p, _ := strconv.Atoi(port); p > 0 { // port is valid
			addr = host
		}
	}

	bp.mux.RLock()
	defer bp.mux.RUnlock()

	if len(bp.matchers) == 0 {
		return false
	}

	var matched bool
	for _, matcher := range bp.matchers {
		if matcher == nil {
			continue
		}
		if matcher.Match(addr) {
			matched = true
			break
		}
	}
	return !bp.reversed && matched ||
		bp.reversed && !matched
}

// Reload parses config from r, then live reloads the bypass.
func (bp *bypasser) Reload(r io.Reader) error {
	var matchers []Matcher
	var period time.Duration
	var reversed bool

	if r == nil || bp.Stopped() {
		return nil
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		ss := splitLine(line)
		if len(ss) == 0 {
			continue
		}
		switch ss[0] {
		case "reload": // reload option
			if len(ss) > 1 {
				period, _ = time.ParseDuration(ss[1])
			}
		case "reverse": // reverse option
			if len(ss) > 1 {
				reversed, _ = strconv.ParseBool(ss[1])
			}
		default:
			matchers = append(matchers, NewMatcher(ss[0]))
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	bp.mux.Lock()
	defer bp.mux.Unlock()

	bp.matchers = matchers
	bp.period = period
	bp.reversed = reversed

	return nil
}

// Period returns the reload period.
func (bp *bypasser) Period() time.Duration {
	if bp.Stopped() {
		return -1
	}

	bp.mux.RLock()
	defer bp.mux.RUnlock()

	return bp.period
}

// Stop stops reloading.
func (bp *bypasser) Stop() {
	select {
	case <-bp.stopped:
	default:
		close(bp.stopped)
	}
}

// Stopped checks whether the reloader is stopped.
func (bp *bypasser) Stopped() bool {
	select {
	case <-bp.stopped:
		return true
	default:
		return false
	}
}

// splitLine splits a line text by white space, mainly used by config parser.
func splitLine(line string) []string {
	if line == "" {
		return nil
	}
	if n := strings.IndexByte(line, '#'); n >= 0 {
		line = line[:n]
	}
	line = strings.Replace(line, "\t", " ", -1)
	line = strings.TrimSpace(line)

	var ss []string
	for _, s := range strings.Split(line, " ") {
		if s = strings.TrimSpace(s); s != "" {
			ss = append(ss, s)
		}
	}
	return ss
}
