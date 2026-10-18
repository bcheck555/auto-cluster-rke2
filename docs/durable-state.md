# Durable identity and operation storage

The universal node stores its identity in `identity/`, the `formation` operation
in `formation/`, and private credentials in `credentials/`, beneath
`/var/lib/autonomous-rke2`. It reuses the storage primitives below. The
authority-backed `journal/` layout is legacy and is refused during automatic
migration. See [current formation states](state-machine.md).

`identity.NewFileStore(absoluteDirectory)` implements `identity.Store`.
`state.NewFileJournal(absoluteDirectory)` implements `state.Journal`. Constructors
perform no I/O; methods return storage errors. These are local Linux filesystem
implementations, intended for persistent host disks with working `flock`, atomic
rename, and file/directory `fsync`. Network/shared filesystems are unsupported.

The immediate parent must exist. Provision the path beneath trusted ancestors
that other users cannot rename or modify. The store creates its leaf directory
with mode `0700` and files with mode `0600`, owned by the effective user. Existing
directories/files with broader or unexpected permissions, symlink leaf paths,
non-regular records, and hard-linked records are rejected. Existing permissions
are never silently repaired. The stable `.lock` file must never be removed while
any store user is running. Identity and journal may use separate directories or
share a directory and its lock.

Identity generation creates one Ed25519 key pair. Host ID is the hexadecimal
SHA-256 digest of its public key, independent of OS machine-id. The persisted
record contains the private key; returned `HostIdentity` contains only public
material. Reads validate the key pair and ID. Never bake initialized storage
into an image, copy it to another host, or delete it to repair corruption.
`Sign` proves possession without exporting the key and never regenerates a
missing identity. The TLS signer adapter supports plain Ed25519 only. Machine-id
provisioning remains agent/platform integration work.

Journal revision zero denotes absence. Create with expected revision zero and
record revision one; update with record revision exactly `expected + 1`.
Conflicts return `state.ErrConflict` and require re-read/reconciliation. Cluster,
host, and operation kind cannot change; timestamps cannot move backwards. Phase
authorization and legal transitions remain caller responsibilities. Operation
IDs are hashed into filenames, so arbitrary IDs cannot escape the directory.
Missing reads return `state.ErrNotFound`; invalid records or revisions return
`state.ErrInvalid`.

Each versioned record includes a SHA-256 checksum. Checksums detect accidental
corruption, not malicious edits by the storage owner. Reads reject malformed,
oversized, unsupported, checksum-invalid, and semantically invalid records.
`ErrCorrupt` never includes record contents. Corruption never authorizes creation
or overwriting an existing identity or journal operation. Keep evidence and
restore from a trusted backup through an operator-controlled recovery procedure.

Reads and writes take an exclusive, context-cancellable cross-process lock.
Writes sync a private temporary file, atomically rename it over the record, then
sync the directory. Opening also syncs the parent to persist directory creation.
An interrupted write leaves the prior record or the complete replacement. Orphan
`.pending-*` files are ignored and retain private permissions; operators may
remove them with all store users stopped. A failure after rename, including a
directory sync failure, has an uncertain commit outcome: re-read before retrying.
Cancellation prevents a commit if observed before rename; a successful rename
cannot be undone by cancellation. Filesystem calls themselves are not cancellable.

Unit tests cover separate-process creation and revision races, restart stability,
permissions and unsafe file types, malformed/key-inconsistent records, lock
cancellation, and abrupt process exits before and after replacement. These tests
do not simulate hardware power loss or validate guest filesystem durability.
