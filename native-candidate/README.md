# Native Connect workspace

This workspace contains the Connect CLI, integrated Console gateway and native
host adapters. The directory name is retained from development; its public
release dependencies select Meerkat Core and Meta 0.9.0 from crates.io.

The unpublished Core `meerkat-machine-codegen` dependency is included under
`../vendor/core-codegen` at its exact Core 0.9.0 source revision. It retains its
upstream licenses and a standalone Cargo manifest projection.

See [the build guide](../BUILDING.md) for the two Rust workspace entry points,
selected toolchain, source-only binary limits and complete distribution resources.
The public native lockfile must be generated from the actual registry selection;
a historical lock containing local Meta source is not interchangeable.
