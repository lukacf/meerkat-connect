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
That historical MCP example does not establish Linux or Windows server use.

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

## Add an explicitly selected prebuilt native dependency

The optional `setup_acquire_node_prebuilt` capability can supplement an exact
successful Node acquisition with a public prebuilt addon. It is available only
when the host selects a pinned download profile. Check the actual tool list and
`setup_state`; ordinary Node acquisition alone does not enable this capability.
This source path still needs its own installed consumer evidence before it can
be described as qualified on a platform.

The agent researches the dependency's publisher, exact release asset and target.
Submit a new request ID, the original acquisition's job ID and receipt digest,
the host's exact selected Node target, and explicit payload choices. Each payload
identifies its npm lock location, original package archive digest, HTTPS asset
URL, digest-bound `native-asset-<sha256>` ID, and member-to-destination mappings.
The tool derives member digests from the downloaded bytes. Do not invent them or
choose an asset merely because its filename looks similar. The selected target
binds Node executable bytes, version, module ABI, OS, architecture and, on Linux,
the current glibc version. It does not establish that a binary is safe or loads.

Success returns a new `selected-node-prebuilt` acquisition. It preserves the
original npm archive, lock and receipt, then adds a pinned manifest and payloads
in the existing flat closure format. Use this new job and receipt through
`acquired_source` with the existing selected Node installation profile. The
original acquisition is unchanged. Recovery can inspect retained evidence but
does not renew acquisition or installation authority.

Installation keeps npm lifecycle scripts disabled. It verifies the original
offline npm graph, adds only the selected files without overwriting package
contents, and verifies the combined graph. Links, path aliases, mismatched
targets and unbounded archives refuse. Readback checks the retained inputs,
installed payloads and current selected Node executable hash without loading
the addon. Protocol startup, operation authorization, resource boundaries and
original-task completion remain separate checks. A package requiring compilation
or another installation effect still needs an appropriate supported backend.

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
the launch. For target-bound optional closures and explicit prebuilt payloads,
its executable hash must also match the retained target. Readback does not
execute a probe or verify current OS, libc, ABI or startup compatibility.

Each original metadata document remains limited to 1 MiB. Validator output and
the receipt use the existing 64 MiB file budget; the MCP file is bounded by the
freshly derived encoded configuration length, accounting for Unicode escaping
and literal arguments. The library's smaller configuration cap does not apply
to selected installations. Malformed or excessively nested JSON is refused.

The command compares the original and frozen artifact closure, npm project and
lock, every included archive payload at its exact installed location, and the
freshly derived launch configuration. Conditional graphs are recomputed from
the complete retained archives and target; the receipt must match the exact
omission reasons, and excluded packages must remain absent. Nested dependency versions retain their lock
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

An ordinary client importing this bare configuration sees the whole server.
Operation declarations in either selected document do not filter its tool list
or authorize calls. Connect's native protected attachment can separately enforce
an approved subset of exact MCP tool names through the host's current grant and
MCP access configuration. Separate write tools do not, by themselves, rule out
that protected read subset. Initialize and inspect the actual tool contract
before requesting the needed operations through the host's protected review.

An operation-name allowlist does not constrain query semantics, prevent startup
effects or provide filesystem confinement. Check whether an allowed query can
write and whether launching the server has side effects; use separately supplied
resource controls. The filesystem example supplies a task-owned allowed
directory and exercises a read; its server also exposes write tools. See
[operation selection and runtime enforcement](../../sdk/consumer-setup/METADATA.md#operation-selection-and-runtime-enforcement).

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
    npm-target                  exact host target, for conditional graphs
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
`package-lock`, plus every archive ID and `npm-target` for a conditional graph.
The entrypoint is a relative `.js`, `.mjs`
or `.cjs` regular file inside the primary package; its arguments are literal.
There are no generated executable aliases or shell expansion.


Target-specific optional graphs require a matching current acquisition worker
and installer; older deliveries above retain their earlier subset. Keep every
lock-referenced archive, including excluded optional packages. Before selecting
the installed graph, the parser validates all archive identities, integrity,
paths and aggregate limits. `closure/npm-target` records the host-observed Node
executable SHA-256, version, module ABI, platform, architecture and libc. The
installer probes the selected Node and requires an exact match before npm runs.
Use the acquisition-generated record rather than guessing target facts.

A platform-incompatible optional subtree can be omitted with an explicit
`excluded_optional_packages` reason; required edges and shared required rows
remain protected. Every package retained in the selected graph must match its exact installed
files even after npm exits successfully. The full original lock remains
unchanged. Conditional peer/devOptional graphs, unsupported libc and packages
requiring native compilation are outside this subset. Explicit prebuilt addons
remain a separate selection. Acquisition, installation and matching files do
not supply authentication, a native grant, MCP readiness or task completion.

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
an explicitly selected prebuilt addon can use the optional path above. Packages
requiring compilation or other installation scripts need another reviewed backend.
Request/Deployment lifetime on the full path and authentication fields in both
forms remain declarations, not native observations or permission.
Existing native runtime and policy owners are unchanged.
