# Building Meerkat Connect

Connect has two Rust workspaces. The root contains `toolkit-package` and
`toolkit-store`; `native-candidate/Cargo.toml` contains the CLI and native host
adapters. Both use the checked-in dependency locks. Native composition uses
published Core and Meta 0.9.0 crates plus the exact unpublished Core code generator
included under `vendor/` with its upstream licenses.

## Prerequisites

Use Rust 1.97.0, the selected build toolchain, on a supported macOS or Linux host
with its normal compiler and platform libraries. The manifests declare Rust 1.94
and edition 2024; the complete dependency graph has not been separately qualified
on that minimum. Python SDK tooling requires Python 3.11 or later. The TypeScript
SDK requires Node 22 or later. Use the package locks for JavaScript dependencies.

## Build a complete local installation

First download, verify and extract a complete CLI archive using the
[README instructions](README.md#install-and-use). That archive supplies the
matching integration library, runtimes and setup resources. Select its absolute
prefix path and resource digest:

| Platform | Complete CLI archive | SHA-256 of `libexec/meerkat-connect/resources.json` |
| --- | --- | --- |
| macOS arm64 | [meerkat-connect-0.9.0-macos-arm64.tar.gz](https://github.com/lukacf/meerkat-connect/releases/download/v0.9.0/meerkat-connect-0.9.0-macos-arm64.tar.gz) | `cbdc8c838413a732ebe4dbcca5e43da388d1c653beca3cfce102574401b61075` |
| Linux x86_64 | [meerkat-connect-0.9.0-linux-x86_64.tar.gz](https://github.com/lukacf/meerkat-connect/releases/download/v0.9.0/meerkat-connect-0.9.0-linux-x86_64.tar.gz) | `3280c10bef460edb19dba38099f97a115b7d49856e9dd9a092efa2a9097d5d5d` |

For example, for macOS arm64, from the source checkout:

```sh
connect_prefix=/absolute/path/to/meerkat-connect-macos-arm64
export MEERKAT_CONNECT_RESOURCES_SHA256=cbdc8c838413a732ebe4dbcca5e43da388d1c653beca3cfce102574401b61075
./scripts/repo-cargo +1.97.0 build \
  --manifest-path native-candidate/Cargo.toml --locked --release \
  -p meerkat-connect --features console,toolkit-mobkit/native-host \
  --bin meerkat-connect --bin toolkit_gateway
connect_target=$(./scripts/repo-cargo --print-env | sed -n 's/^CARGO_TARGET_DIR=//p')
cp "$connect_target/release/meerkat-connect" "$connect_prefix/bin/meerkat-connect"
cp "$connect_target/release/toolkit_gateway" "$connect_prefix/bin/toolkit_gateway"
```

On Linux, select the Linux prefix and digest from the table. The compiled digest
binds the executable to that resource inventory; retain the complete prefix:

```text
<prefix>/bin/meerkat-connect
<prefix>/bin/toolkit_gateway
<prefix>/libexec/meerkat-connect/resources.json
<prefix>/libexec/meerkat-connect/...
```

The repository wrapper uses Git to find the checkout and selects an isolated
Cargo home and target. For an unpacked source archive without `.git`, use ordinary
`cargo +1.97.0` with the same arguments and an explicit, separate
`CARGO_TARGET_DIR`. Copy binaries from that directory's `release/` subdirectory.
Use one writer per target directory.

Compilation can omit `MEERKAT_CONNECT_RESOURCES_SHA256` for source-only work.
Such a binary cannot prepare integrations, even if a resource directory is later
placed beside it. A complete installation needs the matching build-time digest
and prefix above.

## SDKs

The main SDK distributions are the release assets
[`meerkat_toolkit-0.9.0-py3-none-any.whl`](https://github.com/lukacf/meerkat-connect/releases/download/v0.9.0/meerkat_toolkit-0.9.0-py3-none-any.whl)
and [`rkat-toolkit-0.9.0.tgz`](https://github.com/lukacf/meerkat-connect/releases/download/v0.9.0/rkat-toolkit-0.9.0.tgz).
See the [Python](docs/site/sdks/python.mdx) and
[TypeScript](docs/site/sdks/typescript.mdx) pages for installation. These are
GitHub release assets; no Toolkit registry upload is required.

Python source is under `sdk/python`. Its optional extras select service and
native-host dependencies. `sdk/agno/stage.py` and `sdk/services/stage.py` project
explicit source allowlists from that tree into separate adopted distributions.

For TypeScript source, run `npm ci --ignore-scripts`, `npm run build`, then
`npm pack --ignore-scripts` in `sdk/typescript`. Activepieces has its own package
and scripts under `sdk/activepieces`; its build requires the checked-in vendor
manifest, source and license tree. Keep those hashed upstream inputs intact.

## Source checks and documentation

The default GitHub Actions check uses Python 3.12 and Node 22. Run the same
lightweight checks from the repository root:

```sh
python3 -m unittest -v \
  scripts.test_package_connect_resources \
  scripts.test_assemble_connect_product
python3 scripts/check-docs.py
npm --prefix sdk/typescript ci --ignore-scripts --no-audit --no-fund
node --test sdk/typescript/tests/console-setup-panel.test.mjs
```

The Python tests use only the standard library and temporary inert archives.
The panel tests use the locked JSDOM dependency and import the embedded
JavaScript directly, without a TypeScript build. These checks do not build or
run native executables, install integration donors, or contact live providers.
Platform-specific Python controls may skip when the host lacks their filesystem
behavior. Native builds and installed-product acceptance remain separate.

Run the Rust source tests separately:

```sh
./scripts/repo-cargo +1.97.0 test --manifest-path Cargo.toml --locked \
  -p toolkit-package -p toolkit-store
python3 scripts/check-docs.py
```

The documentation check covers navigation, frontmatter and local links. Source
tests include their synthetic fixtures. Live service, deployment and hardware
checks use separate scoped environments.

Catalogs are committed release inputs. Historical private evidence locators
remain in their provenance, but rebuilding that evidence is not a public build
step. Some maintainer packaging scripts retain development defaults and need
explicit release inputs. The commands above build from this source and the
published platform resources without a private checkout or acceptance ledger.
See [SOURCE-PROVENANCE.md](SOURCE-PROVENANCE.md) before changing catalog bytes.
