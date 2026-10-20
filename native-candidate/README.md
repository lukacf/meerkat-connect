# Native Connect workspace

This workspace contains the Connect CLI, integrated Console gateway, native
host adapters and `toolkit-store`. The directory name is retained from development.
The portable root workspace owns `toolkit-package`; its lockfile remains separate.

The checked-in native workspace selects the r9 development pair:

- [Meerkat Core `9281f3b0`](https://github.com/lukacf/meerkat/commit/9281f3b05b846ff31f9d74a146b8020c507aa818).
- [Meerkat Meta `2ea41584`](https://github.com/lukacf/meerkat-meta/commit/2ea415849867ad2cfddee4090a9685c9ec11457e).

`Cargo.toml` and `Cargo.lock` retain this r9 graph, including the
registry-edge patches to those exact sources. The unpublished
`meerkat-machine-codegen` crate now comes directly from the same Core Git
revision. The retained `vendor/core-codegen` tree belongs to the v0.9.0 release
composition and is not selected by this development graph.

Temporary 0.9.4 preview compositions use separately selected build inputs; they
do not change these checked-in pins or establish final SDK qualification.

See [the build guide](../BUILDING.md) for locked source-only builds and complete
distribution prerequisites. This development selection does not replace the
published v0.9.0 archives, resources or SDK assets. Checking out `v0.9.0` selects
the released registry/vendor composition described by that tag's build guide.
Resolution and compilation do not establish installed-host or business success.
