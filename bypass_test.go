package bypass

import (
	"fmt"
	"testing"
)

var bypassContainTests = []struct {
	patterns []string
	reversed bool
	addr     string
	bypassed bool
}{
	// empty pattern
	{[]string{""}, false, "", false},
	{[]string{""}, false, "192.168.1.1", false},
	{[]string{""}, true, "", false},
	{[]string{""}, true, "192.168.1.1", false},

	// IP address
	{[]string{"192.168.1.1"}, false, "192.168.1.1", true},
	{[]string{"192.168.1.1"}, true, "192.168.1.1", false},
	{[]string{"192.168.1.1"}, false, "192.168.1.2", false},
	{[]string{"192.168.1.1"}, true, "192.168.1.2", true},
	{[]string{"0.0.0.0"}, false, "0.0.0.0", true},
	{[]string{"0.0.0.0"}, true, "0.0.0.0", false},

	// CIDR address
	{[]string{"192.168.1.0/0"}, false, "1.2.3.4", true},
	{[]string{"192.168.1.0/0"}, true, "1.2.3.4", false},
	{[]string{"192.168.1.0/8"}, false, "192.1.0.255", true},
	{[]string{"192.168.1.0/8"}, true, "192.1.0.255", false},
	{[]string{"192.168.1.0/8"}, false, "191.1.0.255", false},
	{[]string{"192.168.1.0/8"}, true, "191.1.0.255", true},
	{[]string{"192.168.1.0/16"}, false, "192.168.0.255", true},
	{[]string{"192.168.1.0/16"}, true, "192.168.0.255", false},
	{[]string{"192.168.1.0/16"}, false, "192.0.1.255", false},
	{[]string{"192.168.1.0/16"}, true, "192.0.0.255", true},
	{[]string{"192.168.1.0/24"}, false, "192.168.1.255", true},
	{[]string{"192.168.1.0/24"}, true, "192.168.1.255", false},
	{[]string{"192.168.1.0/24"}, false, "192.168.0.255", false},
	{[]string{"192.168.1.0/24"}, true, "192.168.0.255", true},
	{[]string{"192.168.1.1/32"}, false, "192.168.1.1", true},
	{[]string{"192.168.1.1/32"}, true, "192.168.1.1", false},
	{[]string{"192.168.1.1/32"}, false, "192.168.1.2", false},
	{[]string{"192.168.1.1/32"}, true, "192.168.1.2", true},

	// plain domain
	{[]string{"www.example.com"}, false, "www.example.com", true},
	{[]string{"www.example.com"}, true, "www.example.com", false},
	{[]string{"http://www.example.com"}, false, "http://www.example.com", true},
	{[]string{"http://www.example.com"}, true, "http://www.example.com", false},
	{[]string{"http://www.example.com"}, false, "http://example.com", false},
	{[]string{"http://www.example.com"}, true, "http://example.com", true},
	{[]string{"www.example.com"}, false, "example.com", false},
	{[]string{"www.example.com"}, true, "example.com", true},

	// host:port
	{[]string{"192.168.1.1"}, false, "192.168.1.1:80", true},
	{[]string{"192.168.1.1"}, true, "192.168.1.1:80", false},
	{[]string{"192.168.1.1:80"}, false, "192.168.1.1", false},
	{[]string{"192.168.1.1:80"}, true, "192.168.1.1", true},
	{[]string{"192.168.1.1:80"}, false, "192.168.1.1:80", false},
	{[]string{"192.168.1.1:80"}, true, "192.168.1.1:80", true},
	{[]string{"192.168.1.1:80"}, false, "192.168.1.1:8080", false},
	{[]string{"192.168.1.1:80"}, true, "192.168.1.1:8080", true},

	{[]string{"example.com"}, false, "example.com:80", true},
	{[]string{"example.com"}, true, "example.com:80", false},
	{[]string{"example.com:80"}, false, "example.com", false},
	{[]string{"example.com:80"}, true, "example.com", true},
	{[]string{"example.com:80"}, false, "example.com:80", false},
	{[]string{"example.com:80"}, true, "example.com:80", true},
	{[]string{"example.com:80"}, false, "example.com:8080", false},
	{[]string{"example.com:80"}, true, "example.com:8080", true},

	// domain wildcard

	{[]string{"*"}, false, "", false},
	{[]string{"*"}, false, "192.168.1.1", true},
	{[]string{"*"}, false, "192.168.0.0/16", true},
	{[]string{"*"}, false, "http://example.com", true},
	{[]string{"*"}, false, "example.com:80", true},
	{[]string{"*"}, true, "", false},
	{[]string{"*"}, true, "192.168.1.1", false},
	{[]string{"*"}, true, "192.168.0.0/16", false},
	{[]string{"*"}, true, "http://example.com", false},
	{[]string{"*"}, true, "example.com:80", false},

	// sub-domain
	{[]string{"*.example.com"}, false, "example.com", false},
	{[]string{"*.example.com"}, false, "http://example.com", false},
	{[]string{"*.example.com"}, false, "www.example.com", true},
	{[]string{"*.example.com"}, false, "http://www.example.com", true},
	{[]string{"*.example.com"}, false, "abc.def.example.com", true},

	{[]string{"*.*.example.com"}, false, "example.com", false},
	{[]string{"*.*.example.com"}, false, "www.example.com", false},
	{[]string{"*.*.example.com"}, false, "abc.def.example.com", true},
	{[]string{"*.*.example.com"}, false, "abc.def.ghi.example.com", true},

	{[]string{"**.example.com"}, false, "example.com", false},
	{[]string{"**.example.com"}, false, "www.example.com", true},
	{[]string{"**.example.com"}, false, "abc.def.ghi.example.com", true},

	// prefix wildcard
	{[]string{"*example.com"}, false, "example.com", true},
	{[]string{"*example.com"}, false, "www.example.com", true},
	{[]string{"*example.com"}, false, "abc.defexample.com", true},
	{[]string{"*example.com"}, false, "abc.def-example.com", true},
	{[]string{"*example.com"}, false, "abc.def.example.com", true},
	{[]string{"*example.com"}, false, "http://www.example.com", true},
	{[]string{"*example.com"}, false, "e-xample.com", false},

	{[]string{"http://*.example.com"}, false, "example.com", false},
	{[]string{"http://*.example.com"}, false, "http://example.com", false},
	{[]string{"http://*.example.com"}, false, "http://www.example.com", true},
	{[]string{"http://*.example.com"}, false, "https://www.example.com", false},
	{[]string{"http://*.example.com"}, false, "http://abc.def.example.com", true},

	{[]string{"www.*.com"}, false, "www.example.com", true},
	{[]string{"www.*.com"}, false, "www.abc.def.com", true},

	{[]string{"www.*.*.com"}, false, "www.example.com", false},
	{[]string{"www.*.*.com"}, false, "www.abc.def.com", true},
	{[]string{"www.*.*.com"}, false, "www.abc.def.ghi.com", true},

	{[]string{"www.*example*.com"}, false, "www.example.com", true},
	{[]string{"www.*example*.com"}, false, "www.abc.example.def.com", true},
	{[]string{"www.*example*.com"}, false, "www.e-xample.com", false},

	{[]string{"www.example.*"}, false, "www.example.com", true},
	{[]string{"www.example.*"}, false, "www.example.io", true},
	{[]string{"www.example.*"}, false, "www.example.com.cn", true},

	{[]string{".example.com"}, false, "www.example.com", true},
	{[]string{".example.com"}, false, "example.com", true},
	{[]string{".example.com"}, false, "www.example.com.cn", false},

	{[]string{"example.com*"}, false, "example.com", true},
	{[]string{"example.com:*"}, false, "example.com", false},
	{[]string{"example.com:*"}, false, "example.com:80", false},
	{[]string{"example.com:*"}, false, "example.com:8080", false},
	{[]string{"example.com:*"}, false, "example.com:http", true},
	{[]string{"example.com:*"}, false, "http://example.com:80", false},

	{[]string{"*example.com*"}, false, "example.com:80", true},
	{[]string{"*example.com:*"}, false, "example.com:80", false},

	{[]string{".example.com:*"}, false, "www.example.com", false},
	{[]string{".example.com:*"}, false, "http://www.example.com", false},
	{[]string{".example.com:*"}, false, "example.com:80", false},
	{[]string{".example.com:*"}, false, "www.example.com:8080", false},
	{[]string{".example.com:*"}, false, "http://www.example.com:80", true},
}

func TestBypassContains(t *testing.T) {
	for i, tc := range bypassContainTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			bp := NewBypasserPatterns(tc.reversed, tc.patterns...)
			if bp.Bypass(tc.addr) != tc.bypassed {
				t.Errorf("#%d test failed: %v, %s", i, tc.patterns, tc.addr)
			}
		})
	}
}
