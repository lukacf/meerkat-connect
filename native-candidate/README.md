# Native Connect workspace

This workspace contains the Connect CLI, integrated Console gateway, native
host adapters and `toolkit-store`. The directory name is retained from development.
The portable root workspace owns `toolkit-package`; its lockfile remains separate.

The checked-in native workspace selects the 0.9.4 preview development pair:

- [Meerkat Core `56df4b7a`](https://github.com/lukacf/meerkat/commit/56df4b7a6f6474e9598764549624af3cefeaa048).
- [Meerkat Meta `ff4d271e`](https://github.com/lukacf/meerkat-meta/commit/ff4d271ecfb01653d6cf27e2b5fa87799e9f6a1b).

`Cargo.toml` and `Cargo.lock` retain this preview graph, including the
registry-edge patches to those exact sources. The unpublished
`meerkat-machine-codegen` crate now comes directly from the same Core Git
revision. The retained `vendor/core-codegen` tree belongs to the v0.9.0 release
composition and is not selected by this development graph.

These immutable preview pins support development testing; they are not final
release qualification. The corresponding Meta
[Python SDK](https://github.com/lukacf/meerkat-meta/tree/ff4d271ecfb01653d6cf27e2b5fa87799e9f6a1b/sdk/python)
and [TypeScript SDK](https://github.com/lukacf/meerkat-meta/tree/ff4d271ecfb01653d6cf27e2b5fa87799e9f6a1b/sdk/typescript)
come from the same revision. Canonical SDK package version/pin selection and
installed native runtime acceptance remain separate.

See [the build guide](../BUILDING.md) for locked source-only builds and complete
distribution prerequisites. This development selection does not replace the
published v0.9.0 archives, resources or SDK assets. Checking out `v0.9.0` selects
the released registry/vendor composition described by that tag's build guide.
Resolution and compilation do not establish installed-host or business success.
