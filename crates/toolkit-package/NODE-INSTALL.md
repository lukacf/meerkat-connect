# Install an explicitly selected local Node MCP server

The trusted local installer can turn an agent's exact package choice into a
new npm environment and a concrete stdio MCP configuration. The package need
not appear in Toolkit's catalog. The agent researches and chooses it; the host
selects the input digest, trusted validator, installer and runtime executables.

This path uses `IntegrationPackage` with either full `ActivationManifest` or
plain `LocalSoftwareDeclaration`, validated by the existing package owner. It
does not activate native `find_and_install`, attach tools to an
agent, complete authentication or resume the original task.

The exact `@modelcontextprotocol/server-filesystem@2026.8.31` selection passed
fresh installation and a separate restore on macOS arm64 with Node 24.19.0,
with network access denied. For each, an official Python MCP client consumed
the emitted configuration, initialized, listed 14 tools, read a task-owned
fixture, observed denial outside its selected directory and closed. See the
[installation evidence](../../docs/verification/20261003-selected-node/final-delivery/acceptance.json)
and [component acceptance](../../docs/verification/20261003-selected-node/acceptance.json).
This verifies that selected package and platform, not all Node packages.
Linux and Windows consumer support is not established.

## Select the document form

Current source supports the plain service form in the
[metadata guide](../../sdk/consumer-setup/METADATA.md). It requires one independent
local Node service with an exact pinned closure, connection-wide operations and
no known or unresolved selected-strategy requirements. Custom host, lifecycle,
enforcement and selected-resource obligations remain on the full activation path;
never discard them from the researched package to fit this form.

| Input form | Fixed selected file | Planner flag | Installer and readback flag | Canonical identity |
| --- | --- | --- | --- | --- |
| Full activation | `activation.json` | `--selection` | Omit `--document-kind` | `manifest_digest` |
| Plain software | `declaration.json` | `--declaration` | `--document-kind local_software_declaration` | `document_kind` plus `declaration_digest` |

Use the same form for installation, reconciliation and explicit restore. The
new form requires coherent current installer/planner binaries, not the historical
delivery below. For that form, use current executables in the install/readback
examples, add the flag above and supply the exact raw declaration hash. Its
canonical digest never replaces `--selection-sha256`. Crossed forms, unknown kinds
and mismatched receipt identity refuse. Earlier execution claims remain evidence
only for their retained full activation source and selected artifacts.

## Install the selected bundle

Use `install-library-consumer.py` and the trusted `toolkit-node-plan` executable
delivered together in `dist/selected-node-20261003`. Earlier offline library
bundles do not include this selected-package mode. Supply absolute paths and a
new destination whose parent already exists and remains host-controlled.

```sh
env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
  /absolute/python3.11 -I /absolute/selected-node-20261003/install-library-consumer.py \
  --selected-node /absolute/reviewed-node-bundle \
  --selection-sha256 HOST_SELECTED_RAW_ACTIVATION_SHA256 \
  --component node-server \
  --validator /absolute/selected-node-20261003/toolkit-node-plan \
  --node /absolute/node \
  --npm-cli /absolute/npm/bin/npm-cli.js \
  --destination /absolute/new/selected-node-install
```

Replace `node-server` with the selected component ID. The digest is the SHA-256
of the exact reviewed selected file (`activation.json` or `declaration.json`),
not the canonical manifest or declaration digest reported by the validator. Computing a hash does not establish that its contents
are approved. This invocation is trusted local effect admission, not an
untrusted agent tool whose arguments carry authority.

The installer freezes the documents, invokes the trusted validator on those
copies, verifies the selected artifact closure, seeds a private npm cache and
runs ordinary `npm ci --offline --ignore-scripts --bin-links=false`. It checks
the installed file graph and archive payloads before publishing:

- `ready/mcp.json`: concrete absolute Node and script paths plus literal args.
- `ready/installed.json`: observed software identity, input hashes, launch argv
  and the selected form's canonical identity from the table above.

The `ready` directory means the installation outputs passed these checks. It
does not mean the MCP protocol, account or business operation is ready. The
installer does not launch the selected server or guess a `profiles` command.
A failed attempt retains its partial directory and step logs; keep it unused
and select another new directory after correcting the cause.

## Reconcile an existing selected installation

The current source installer also supports `--verify-existing`. Earlier
deliveries may not include it. Supply the original selected bundle and raw
selection digest and matching document-kind flag, component ID, trusted validator and Node path, and the
existing destination:

```sh
env -i PATH=/usr/bin:/bin \
  /ABS/python3.11 -I -B /ABS/current/install-library-consumer.py \
  --selected-node /ABS/reviewed-node-bundle \
  --selection-sha256 HOST_SELECTED_RAW_ACTIVATION_SHA256 \
  --component node-server \
  --validator /ABS/trusted/toolkit-node-plan \
  --node /ABS/node \
  --destination /ABS/existing/selected-node-install \
  --verify-existing
```

Readback freezes the original metadata in private temporary storage under the
host's `TMPDIR`, or `/tmp` when unset. The supplied directory must be absolute,
existing and outside both the selected bundle and destination after resolving
symlinks. Invalid locations are refused before temporary-file creation; the host
must permit writes there. Readback invokes only the trusted
canonical validator on those copies. Child stdout is bounded, stderr discarded,
stdin closed, the environment minimal, and one deadline spans pipe completion
and process exit. Interruption joins the child and terminates its process group.
There is no Node, npm, donor, server or runtime-probe execution. `--npm-cli` is
unnecessary in readback mode; if carried over from the install invocation it is
ignored. The selected Node path resolves to an executable regular file and binds
the launch, but its bytes, version and compatibility are not verified.

Each original metadata document remains limited to 1 MiB. Validator output and
the receipt use the existing 64 MiB file budget; the MCP file is bounded by the
freshly derived encoded configuration length, accounting for Unicode escaping
and literal arguments. The library's smaller configuration cap does not apply
to selected installations. Malformed or excessively nested JSON is refused.

The command compares the original and frozen artifact closure, npm project and
lock, every archive payload at its exact installed location, and the freshly
derived launch configuration. Nested dependency versions retain their lock
locations. The historical receipt must agree with independently derived bindings;
it never grants authority. `ready` must contain exactly `installed.json` and
`mcp.json`; pending or crossed publication, changed inputs or receipt bindings,
extra executable payloads, symlinks and special files cause refusal. Generated
hidden lock metadata, npm caches, step logs and historical runtime probes are
outside this proof.

The result scope is `retained_payload_and_launch_binding_only`. It does not mean
runtime health, authenticated account access, operation permission or readiness.
Selected readback has a trusted metadata child and private scratch writes;
library readback remains inert. It requests no network access and never writes
to, repairs, installs into or promotes the observed destination. The host must
maintain exclusive custody of originals, executables and destination throughout
the observation. Bounded no-follow reads do not form an atomic snapshot or
protect against a malicious concurrent writer. On refusal, preserve the existing
destination for inspection; readback never silently retries installation.

## Launch through the consuming host

Import `ready/mcp.json` into an MCP host that accepts `mcpServers` stdio entries,
or read its `command` and `args` in a standard MCP client. The host owns the
launch environment, credentials, resource access, operation approval and joined
process shutdown. The configuration does not clear inherited environment.

The client sees the whole server. Operation declarations in either selected
document do not filter its tool list or authorize writes. Initialize, inspect
the actual tool contract and perform only separately permitted calls. The
filesystem example supplies a task-owned allowed directory and exercises a read;
its server also exposes write tools.

Restore the same software choice by repeating the install into another new
destination with the retained inputs and selected runtimes. Paths in `mcp.json`
are specific to that installation. The host owns switching consumers and closing
the prior process. Software restoration does not restore credentials, application
state or grants, and does not undo or replay operations.

## Prepare the exact inputs

The optional [setup acquisition tool](../../sdk/consumer-setup/NODE-ACQUISITION.md)
can prepare this layout from an agent-selected public npm package and version.
It preserves the ordinary npm lock and calls this installer's archive-closure
validator before publication. Manual staging remains supported.

Retain nonsecret metadata, the selected server tarball and the complete npm
closure in this layout:

```text
reviewed-node-bundle/
  package.json                  Toolkit IntegrationPackage
  activation.json               Toolkit ActivationManifest
  artifact.tgz                  exact selected npm server package
  closure/
    package-json                npm project package.json bytes
    package-lock                npm package-lock.json bytes
    archive-ID                  exact dependency tarball bytes
```

For plain software, replace `activation.json` in this layout with fixed
`declaration.json`; never include both. The artifact and closure paths are
unchanged. The top-level `package.json` is Toolkit metadata. The npm project lives under
`closure/package-json` to keep these two documents distinct. Its sole dependency
must be the selected package name with `file:./artifact.tgz`; `private` must be
`true`. The unchanged npm lock must be version 3. Retain every referenced
dependency archive. Nested installed versions are supported and checked at
their exact lock paths. The installer does not resolve registry versions or
download missing inputs.

Both forms name a `LocalMcp` strategy, one independent Node component, one service
export without events, and one `portable_mcp_entries` name for that component.
Full activation additionally selects its actual local host placement and
lifecycle/enforcement contracts; the plain software declaration does not invent them. Its artifact digest pins `artifact.tgz`.
`ArtifactDependencies::PinnedClosure` pins both reserved IDs `package-json` and
`package-lock`, plus every archive ID. The entrypoint is a relative `.js`, `.mjs`
or `.cjs` regular file inside the primary package; its arguments are literal.
There are no generated executable aliases or shell expansion.

For the full activation form, start from the [inert package](tests/fixtures/node-install/package.json) and
[selection](tests/fixtures/node-install/activation.json) examples when composing
these typed documents. Replace every fixture identity, source, digest, operation
schema, policy/configuration reference and host-owned declaration with the
actual selection. The examples' placeholder values are not a usable package.
Never put secrets in these documents; validation does not detect secret content.

## Use the existing validation owner

The standalone command is built from Toolkit only:

```sh
./scripts/repo-cargo build -p toolkit-package --bin toolkit-node-plan
```

Select the resulting executable from the build's reported target directory.
Inspect a choice without installing it:

```sh
/absolute/trusted/toolkit-node-plan \
  --package /absolute/reviewed-node-bundle/package.json \
  --selection /absolute/reviewed-node-bundle/activation.json \
  --component node-server
```

For plain software, replace `--selection .../activation.json` with
`--declaration .../declaration.json` in that command. The flags are exclusive.
The CLI parses the two bounded regular files, calls the matching
`ActivationManifest::validate` or `LocalSoftwareDeclaration::validate`, and
derives `NodeInstallPlan` from that owner's private validated proof. The JSON
projection binds package identity/content, the selected form's canonical
identity, strategy, component/export, artifact/closure, entrypoint and MCP name. It is not a second semantic manifest. The installer
invokes this executable again on its own frozen files; it never accepts an old
serialized plan as proof of authorization or validation.

This backend accepts bounded regular npm archive files and directories, exact
HTTPS registry dependency rows, and literal JavaScript entrypoints. It refuses
links, workspaces, bundled dependencies, development-only rows, archive path
aliases and unsupported paths. Lifecycle scripts and binary links are disabled;
packages requiring those installation steps need another reviewed backend.
Request/Deployment lifetime on the full path and authentication fields in both
forms remain declarations, not native observations or permission.
Existing native runtime and policy owners are unchanged.
