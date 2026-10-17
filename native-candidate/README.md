# Native Connect workspace

This workspace contains the Connect CLI, integrated Console gateway and native
host adapters. The directory name is retained from development. The portable
root workspace and its package/store lock remain separate and unchanged.

The native workspace selects the exact development pair:

- [Meerkat Core `efd313d4`](https://github.com/lukacf/meerkat/commit/efd313d44807d3e93f6808a127fa157be84dee05).
- [Meerkat Meta `669f54fa`](https://github.com/lukacf/meerkat-meta/commit/669f54fafafd82747c8cd9022e602a774cb4559d).

`Cargo.toml` and `Cargo.lock` retain the Core/Meta 0.9.1 graph, including the
registry-edge patches to those exact sources. The unpublished
`meerkat-machine-codegen` crate now comes directly from the same Core Git
revision. The retained `vendor/core-codegen` tree belongs to the v0.9.0 release
composition and is not selected by this development graph.

See [the build guide](../BUILDING.md) for locked source-only builds and complete
distribution prerequisites. This development selection does not replace the
published v0.9.0 archives, resources or SDK assets. Checking out `v0.9.0` selects
the released registry/vendor composition described by that tag's build guide.
Resolution and compilation do not establish installed-host or business success.
