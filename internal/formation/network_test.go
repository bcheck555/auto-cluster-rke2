package formation

import (
	"errors"
	"net"
	"testing"
)

func TestNetworkSelectionSurvivesRKE2InterfacesAndRejectsAmbiguousUplinks(t *testing.T) {
	flags := net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	interfaces := []net.Interface{{Name: "rke2lab0", Flags: flags}, {Name: "cni0", Flags: flags}, {Name: "flannel.1", Flags: flags}, {Name: "veth1234", Flags: flags}}
	addresses := map[string]string{"rke2lab0": "192.168.250.241/24", "cni0": "10.42.0.1/24", "flannel.1": "10.42.0.0/32", "veth1234": "10.42.0.2/32", "management0": "192.168.1.1/24"}
	get := func(iface net.Interface) ([]net.Addr, error) {
		ip, network, err := net.ParseCIDR(addresses[iface.Name])
		if err != nil {
			return nil, err
		}
		network.IP = ip
		return []net.Addr{network}, nil
	}
	name, address, err := selectNetwork("", interfaces, get)
	if err != nil || name != "rke2lab0" || address != "192.168.250.241" {
		t.Fatal("CNI broke post-boot selection", name, address, err)
	}
	interfaces = append(interfaces, net.Interface{Name: "management0", Flags: flags})
	if _, _, err := selectNetwork("", interfaces, get); !errors.Is(err, ErrWaiting) {
		t.Fatal("ambiguous physical NIC guessed", err)
	}
	name, address, err = selectNetwork("rke2lab0", interfaces, get)
	if err != nil || name != "rke2lab0" || address != "192.168.250.241" {
		t.Fatal("configured uplink rejected", name, address, err)
	}
}
