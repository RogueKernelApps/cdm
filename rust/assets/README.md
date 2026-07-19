# Embedded guest root filesystems

CDM embeds one official Alpine minirootfs for each supported VM architecture.
`rootfs.rs` selects the archive at compile time, so an AArch64 binary cannot
silently boot the x86-64 guest (or vice versa).

The versions and archive digests are pinned in `packaging/versions.env`.
`alpine-rootfs.lock.json` is generated from the archives themselves and records
every installed package, its declared license, source package, and Alpine build
commit. Regenerate it after changing either archive:

```bash
python3 assets/update-alpine-lock.py
```

The lock file is an inventory, not corresponding source. A redistributable CDM
release must ship the matching source companion required by the package
licenses. `packaging/package.sh release` owns that release contract; do not
describe the binary archives in this directory as source code.
