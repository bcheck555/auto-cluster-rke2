package hostagent

import (
	"net"
	"regexp"
	"testing"
)

func TestFlannelSubnetSelectionDoesNotDependOnNodeNICNames(t *testing.T) {
	for _, test := range []struct {
		cidr           string
		match, exclude []string
	}{{"192.168.250.0/24", []string{"192.168.250.11", "192.168.250.244"}, []string{"10.42.0.1", "127.0.0.1", "192.168.251.1", "ens3", "enp2s0"}}, {"192.168.250.0/23", []string{"192.168.250.11", "192.168.251.244"}, []string{"192.168.249.255", "192.168.252.1", "10.43.0.1"}}} {
		_, network, _ := net.ParseCIDR(test.cidr)
		pattern, err := subnetPattern(network)
		if err != nil {
			t.Fatal(err)
		}
		matcher, err := regexp.Compile(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range test.match {
			if !matcher.MatchString(ip) {
				t.Fatalf("%s excludes %s", pattern, ip)
			}
		}
		for _, ip := range test.exclude {
			if matcher.MatchString(ip) {
				t.Fatalf("%s includes %s", pattern, ip)
			}
		}
	}
	for _, cidr := range []string{"10.0.0.0/8", "10.42.1.0/24", "10.43.0.0/16", "0.0.0.0/0"} {
		_, network, _ := net.ParseCIDR(cidr)
		if _, err := subnetPattern(network); err == nil {
			t.Fatal("CNI-overlapping network accepted", cidr)
		}
	}
}
