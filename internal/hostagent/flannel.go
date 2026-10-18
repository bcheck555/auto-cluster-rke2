package hostagent

import (
	"net"
	"strconv"
	"strings"
)

// A HelmChartConfig is shared by all nodes. Matching the common IPv4 subnet
// avoids putting one server's NIC name into every Flannel pod. It also works
// without a default route and excludes the pod/service networks.
func flannelUplink(p Plan) (string, error) {
	iface, err := net.InterfaceByName(p.Interface)
	if err != nil {
		return "", ErrReconcile
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return "", ErrWaiting
	}
	for _, address := range addresses {
		ip, network, err := net.ParseCIDR(address.String())
		if err == nil && ip.Equal(net.ParseIP(p.NodeIP)) {
			pattern, err := subnetPattern(network)
			if err != nil {
				return "", err
			}
			return "--iface-regex=" + pattern, nil
		}
	}
	return "", ErrReconcile
}

func subnetPattern(network *net.IPNet) (string, error) {
	if network == nil || network.IP.To4() == nil {
		return "", ErrInvalid
	}
	bits, width := network.Mask.Size()
	if width != 32 {
		return "", ErrInvalid
	}
	for _, cidr := range []string{"10.42.0.0/16", "10.43.0.0/16"} {
		_, reserved, _ := net.ParseCIDR(cidr)
		if network.Contains(reserved.IP) || reserved.Contains(network.IP) {
			return "", ErrReconcile
		}
	}
	base := network.IP.Mask(network.Mask).To4()
	parts := make([]string, 4)
	for octet := range 4 {
		remaining := bits - octet*8
		if remaining >= 8 {
			parts[octet] = strconv.Itoa(int(base[octet]))
			continue
		}
		if remaining <= 0 {
			parts[octet] = "[0-9]{1,3}"
			continue
		}
		count := 1 << (8 - remaining)
		values := make([]string, count)
		for index := range count {
			values[index] = strconv.Itoa(int(base[octet]) + index)
		}
		parts[octet] = "(" + strings.Join(values, "|") + ")"
	}
	return "^" + strings.Join(parts, `\.`) + "$", nil
}
