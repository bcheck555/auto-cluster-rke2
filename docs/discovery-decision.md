# Discovery decision: first node first

Accepted deployment model: boot one universal node alone on the intended IPv4
L2 segment, wait for health, then boot additional clones. Every clone uses the
same runtime image and deployment enrollment secret. Networking components
and, for VMs, the hypervisor are the only external runtime infrastructure.

Node-resident UDP multicast uses `239.192.42.42:9444`, TTL 1, with the selected
interface explicitly set so a default route is unnecessary. Probes are bounded,
signed and HMAC-authenticated; replies are unicast to the probe socket and echo
its challenge. This is a private discovery protocol, not mDNS. Fresh nodes use
three probe rounds per convergence attempt and a default 30-second startup
grace. Auto selection requires exactly one suitable IPv4 interface/address;
ambiguous networking waits for explicit configuration.

A pending cluster UUID prevents another visible node from bootstrapping while
RKE2 is starting. When a healthy server appears, fresh nodes enroll with it.
Multiple known UUIDs within the same deployment cause a conflict. Previously
selected nodes always retain their recorded cluster, even with no replies.

Among mutually reachable fresh nodes, lowest host ID is preferred for initial
bootstrap. This reduces simultaneous-start races but is not a consensus
protocol and does not make arbitrary simultaneous boots partition-safe. A
blocked multicast path, failed switch membership, hidden peers, or partitioned
fresh groups can look like an empty network. Boot-first-alone and working L2
reachability are required. Do not claim partition-proof automatic formation.

Discovery advertises public identity, certificate, address, policy, cluster,
phase, role and readiness. Enrollment secrets, registration tokens and private
keys never appear in multicast. Authenticated discovery pins node HTTPS trust;
Kubernetes/etcd serialize subsequent admission. No DHCP extension, DNS server,
external lease, external database or external bootstrap authority is required.
