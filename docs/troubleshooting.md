# Troubleshoot cluster deployment

Use these checks for the universal image and current libvirt scripts. Preserve
initialized disks and state while diagnosing failures. A full rebuild uses
[destroy and create](lab-lifecycle.md#destroy-and-rebuild-a-cluster); back up
application data first.

## A pasted command exits SSH

**Cause:** older runbooks changed shell options with `set -e`/`set -u` or relied
on variables set inside a different root shell.

**Resolution:** reconnect and use the Python commands in [lab lifecycle](lab-lifecycle.md).
Do not depend on the old `$pool` variable. Scripts leave shell options alone.

## YAML loading or plan fails

**Causes:** PyYAML absent from root's interpreter; invalid fields/types; duplicate
keys; or conflicting sibling configs.

**Resolution:** provide [lab requirements](../lab/requirements.txt) in the Python
environment used by `sudo`. Compare YAML with the [template](../clusters/cluster.yaml.example).
Inspect all real `.yaml`/`.yml` in the same directory, including stopped clusters.
Destroy preserves their reservations. Edit or retire obsolete inputs manually.

## Subnet or name collision

**Cause:** identity, hostname prefix, network, or subnet conflicts with sibling
configs, libvirt resources, host routes, or Kubernetes ranges.

**Resolution:** select unique names and a nonoverlapping private subnet; rerun
plan. A network name creates an owned network, not attachment to an existing one.
Add invisible remote pod/service/VPN ranges to `network.reserved_cidrs`. Do not
delete unrelated resources to bypass checks.

## Private file refused

**Causes:** initialization targets an existing file; wrong ownership/mode;
symlink; unsupported shell syntax; or changed key for a saved deployment.

**Resolution:** initialize only absent files. Inspect metadata without printing
contents:

```bash
sudo stat -c '%U %a %F %n' clusters/dev.env
```

Expect root, `600`, and a regular file. Follow the
[private-input rules](cluster-config.md#private-input-format). Restore the original
key if it changed. Do not regenerate keys independently on each node.

## Release verification or capacity check fails

**Causes:** absent ignored artifacts, wrong relative release path, missing trust,
or insufficient disk/RAM.

**Resolution:** resolve release paths from the YAML directory. Restore matching
signed artifacts and trust files or use the [image workflow](offline-images.md).
Do not edit signed manifests. Full new disk sizes and host reserves count even
when qcow2 files initially occupy little space. Plan does not replace these checks.

## New node waits for discovery or enrollment

**Causes:** first node unhealthy; blocked traffic; different keys; wrong
interface/address; incorrect clocks; or pending join.

**Resolution:** on the first node, run:

```bash
sudo systemctl status autonomous-rke2-host-agent.service
sudo journalctl -u autonomous-rke2-host-agent.service -n 100 --no-pager
sudo /usr/local/libexec/autonomous-rke2/host-agent -health
```

Check [network prerequisites and ports](universal-node.md#before-you-begin), unique
stable addresses, clocks, and shared key. Boot the first new node alone; wait for
health before later nodes. A pending reservation does not expire. Resume its
original node; abandoned reservation reconciliation is not implemented.

## Existing cluster fails health after reboot

**Causes:** too few existing voters restarted, or persistent identity/data no
longer matches the recorded cluster.

**Resolution:** rerun create with the same config; it starts previously booted
nodes before waiting for quorum. First-node-alone applies to new formation.
For missing data, changed address/interface, fingerprint, or conflicting IDs,
restore original state/settings. Do not delete journals or reset etcd to force
discovery. Automated quorum reset is not implemented.

## Destroy refuses leftovers

**Causes:** unknown resource consumer; same-named VM outside owned storage;
symlink/mount in pool; or source YAML/`.env` inside a generated directory.

**Resolution:** inspect the destroy plan and ownership error. Manually move
source inputs to a dedicated config directory. Resolve unexpected consumers
without deleting unrelated VMs. Rerun destroy to finish interrupted cleanup.
It needs no readable `.env`. Source YAML and private inputs remain by design.
