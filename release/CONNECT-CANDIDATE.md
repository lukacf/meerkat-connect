# Connect Linux candidate draft

This manual-only workflow is source preparation for the Core/Meta 0.9.4 installed
selection. It does not publish, tag, install on a user host, dispatch another
workflow, or qualify any bytes until its actual producer and verifier succeed.
Connect's native package version and application SDK version are independent
explicit selections, checked against the dispatched source metadata. There is
no default to the public 0.9.0 artifacts or to a development pair.

The existing producer path is used without weakening its acceptance:

1. Fetch each exact public input by URL, SHA-256 and byte size.
2. Check published Core/Meta 0.9.4 tag commits, the selected Cargo manifest/lock,
   complete actual package/feature/dependency graph, and the actual published
   Meta SDK wheel against that release source. Build the Connect wheel from a
   scratch copy of the dispatched `sdk/python` using its existing PEP 517 backend
   and an explicit offline build-tool wheel batch. Compare the complete original
   wheel payload to the dispatched source; retain its command, log and metadata.
3. Project the selected library name/hash/bytes into the existing starter manifest
   shape, explicitly marked as an unpublished candidate input. Run the existing
   `export-setup-starter.py` with that exact manifest and digest to produce all
   six starter files from this source. Then run `package-connect-resources.py`
   with every library/starter/runtime input explicit and retain `build.json`.
4. Build only `toolkit_gateway` through `repo-cargo`, with the resource digest
   bound in the actual command environment. Retain the actual compiler artifact,
   command/log, source inventory, metadata and native build record.
5. Stage through `assemble-connect-product.py`, then run the existing
   `verify_native_gateway_subprocess.py --case installed-product` against the
   staged gateway and the selected installed SDK wheel bytes. Both its success
   and resource-corruption cases must pass their existing cleanup assertions.
6. Final assembly consumes that exact verifier report and all of its original
   records. The emitted scope remains
   `installed_gateway_schema4_resource_startup_and_shutdown_preview` and its
   existing exclusions remain in `assembly.json`.
7. Emit the existing `forge-meta-toolkit-runtime-selection-v1` shape, then invoke
   the selected Meta release's actual `parse_candidate_selection` and
   `read_meta_toolkit_artifacts` reader. Its absence or incompatibility refuses.
8. Upload the whole candidate closure once. A separate job, which executes no
   native product, checks the original upload ID, run/attempt/source and archive
   digest, then attests those same closure/manifest bytes. It does not rebuild.

The source archive is the public dispatched commit. Candidate source SHA,
workflow SHA and dispatch SHA must agree. There is no restored Cargo/target
cache and no secret needed for downloads or native execution. The attestation
job alone receives OIDC/attestation permissions. The GitHub-hosted runner's
actual tool versions and package inventory are retained; the runner image and
system package set are observed, not claimed reproducible from this draft.

## Required inputs still unbound

`connect-release-inputs.json` contains deliberate nulls. It refuses before any
native build. The existing owners must supply all of the following:

- The final dispatched public Connect source commit, its native package version,
  SDK distribution/version, and exact native Cargo manifest/lock hashes.
- The actual published Core and Meta `v0.9.4` source commits. Their complete
  selected Cargo package IDs, features, dependency edges/kinds/target predicates
  and native family membership must match. Workspace IDs alone use the explicit
  `path+workspace:///` comparison form. `expected_resolve` contains `root` and
  the complete sorted `nodes`; native null root/target become empty strings and
  null dependency kind becomes `normal` only for comparison. Raw Cargo metadata
  remains unchanged.
- A complete `files` inventory. Each key is a safe relative locator and each
  value is exactly `{url, size, sha256}`. Only pinned GitHub release assets from
  the named public repositories, PyPI file URLs, and versioned Node downloads
  are accepted. No private bucket, local path or expiring input is accepted.
- The complete selected library archive, Python/Node/pip upstream runtime files
  required by the existing resource packager, acquisition
  Node/npm archives, and selected Node prebuilt policy. `node_build_profile` is
  an optional explicit locator; an empty string means no source-build profile.
  This does not qualify arbitrary source builds or imply a source-build toolchain.
- The original public Meta SDK wheel and complete `source_files` maps for both
  SDKs, from each non-dist-info wheel member to its exact selected repository-
  relative source file. Connect source supplies its own wheel through its current
  build backend; no wheel payload or version is rewritten. The source must
  declare the matching `meerkat-meta==0.9.4` native-host dependency.
- A complete offline SDK build-tool requirements file and wheel batch, including
  the build frontend and the selected source backend requirements. No versions
  are inferred. `--no-isolation` uses only that fresh build environment; the
  existing source-owned backend remains responsible for creating the wheel.
- The exact hashes of the four Forge reader source files in the actual published
  Meta release checkout. The historical r5 Meta source has no installer reader;
  its availability is not implied by a version string. Missing or differing
  reader source refuses before resource/native production.
- One complete offline dependency requirements file and wheel batch. The
  existing Forge reader validates both this batch and the SDK build-tool batch
  before either install: only exact single-hash package pins, with original
  matching wheels, are accepted. Direct URLs, includes and options refuse.
  The verifier installs
  only these pinned bytes and the original just-built SDK wheel, with no
  dependency download or second SDK build.
- SHA-256 of the completed committed input file, supplied with the exact source
  SHA at dispatch. The draft input file is not an accepted release selection.

Clean CI execution does not clean historical prebuilt input provenance. The
producer refuses retained private-host paths in selected JSON/provenance files,
embedded library inventories, wheel metadata and exported logs, preserving all
original bytes. Any rejected library, policy or upstream SDK must be emitted
again by its existing owner in clean CI from a fully supplied current closure. The Connect
wheel and starter are generated in this workflow, so they do not depend on
publication of the same candidate. The library remains an independent input
whose existing owner must provide clean source/build provenance. This workflow
does not invent missing library/tool build receipts. Public availability of an old archive is
not a substitute for that provenance or current source equality.

## Scope and remaining work

This draft was checked by source reading, Python AST parsing, JSON parsing,
YAML parsing and exact patch roundtrip only. No Cargo, packager, verifier, Forge
module, native binary, GitHub job or remote host was executed for this draft.
The selected source and input joins still need a real owner-authorized CI run.
The Linux installed-product scope is narrower than shared setup workflow,
acquisition, account login, model/task completion, installation or another OS.

There is no Connect release workflow or prior trigger policy to extend at the
reviewed public source. This adds only `workflow_dispatch`. Candidate publication,
exact-main CI qualification, consumer acceptance, immutable public asset URLs and
Forge inclusion remain with the existing release owners. An Actions artifact is
not a public release asset and does not satisfy Forge's public-fetch allowlist.
The complete wrapper is required to stay below 2 GiB, matching Forge's public
input/archive bound; an oversized closure refuses before upload/attestation.
The final product archive and its original `.sha256` sidecar are both retained.
The later publisher must publish the accepted original bytes, including the
complete indirect producer records, without sanitizing, rebuilding or resigning.
