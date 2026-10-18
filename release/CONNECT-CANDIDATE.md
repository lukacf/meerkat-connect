# Connect Linux candidate and publication

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

## Accept an exact candidate without write credentials

`accept-publication` accepts an already emitted candidate. It does not run the
build or fetch commands. Use a separate environment without GitHub write
credentials; its verifier and Meta-reader child processes receive a scrubbed
home/configuration and no inherited credential environment.

```sh
python3 scripts/connect-candidate.py accept-publication \
  --request /path/to/selected-publication-request.json \
  --candidate /path/to/candidate-files \
  --meta-source /path/to/selected-meta-checkout \
  --output /path/to/new-acceptance-directory
```

These paths describe a future selected operation, not runnable release inputs
from this draft. The request must contain exactly these nine fields:

| Field | Required value |
| --- | --- |
| `source_sha` | Exact 40-character lowercase Git commit SHA of the candidate's public Connect source. |
| `source_tree` | Exact 40-character lowercase source tree SHA retained by that candidate. |
| `source_ref` | Selected branch ref in `refs/heads/...` form. |
| `run_id`, `run_attempt` | Positive integer identities of the same workflow invocation. |
| `inputs_sha256` | Exact 64-character lowercase SHA-256 of the original committed input selection. |
| `connect_version` | Exact selected native package version in `major.minor.patch` form; not inferred from Core or Meta. |
| `release_id`, `tag` | Positive integer ID and exact tag of the existing release selected for later publication. |

The candidate directory must supply these three original files:

- `connect-linux-candidate.tar.gz`, the complete candidate closure below 2 GiB.
- `connect-candidate.json`, its original attested manifest, at most 32 MiB.
- `connect-provenance.jsonl`, the attestation bundle for both subjects, at most
  32 MiB. Unsigned bundle JSON is not verification evidence.

The repository is fixed to `lukacf/meerkat-connect` and the workflow to
`.github/workflows/connect-candidate.yml`. GitHub's `gh attestation verify`
verifies each subject; the checked result must match the exact source,
workflow, ref, run/attempt, issuer and GitHub-hosted runner. The manifest and
original input selection bind the input digest, native releases and Connect
version. The Meta checkout must be the exact selected published `v0.9.4`
commit, with a clean original `installer/launchkit` package and matching reader
source pins. Neither an SDK wheel nor a separate reader wheel substitutes for
that checkout.

Acceptance performs bounded data-only extraction, preserves original bytes,
and checks the complete retained inventory. The selected Meta package supplies
`parse_candidate_selection`, `packaged_runtime.relocate_selection` and
`selected_runtime_artifacts`; only that owner relocates physical paths in its
in-memory view. The original v1 selection and producer records are not
rewritten. The reader must accept `installed-gateway-assembly` with the exact
installed preview scope, including the original product checksum sidecar.
Development and staging substitutions refuse.

The output directory must not exist. Success writes `acceptance.json` with the
exact request, scope, three asset hashes/sizes, original selection, physical
layout map and owner-validated evidence inventory; `publication` remains
`not_performed`. It also retains `assets/`, `unpacked/`, the layout and both
verified subject results. A refused acceptance may leave partial local files;
it produces no completed acceptance record. Select the exact SHA-256 of the
successful `acceptance.json` independently before handing it to the writer.
This record is a local operation handoff, not a new runtime-selection format.

## Publish only the accepted bytes

`publish-accepted` is the separate write-capable command. It requires an already
public repository and an existing non-draft release whose tag resolves to the
accepted source. It creates no release or tag, changes no release state and
overwrites no conflicting asset. Release creation and authorization remain with
the release owner.

```sh
python3 scripts/connect-candidate.py publish-accepted \
  --accepted /path/to/acceptance-directory \
  --acceptance-sha256 "$SELECTED_ACCEPTANCE_SHA256" \
  --output /path/to/new-publication-observation
```

`--accepted` selects the prior `acceptance.json` and `assets/` directory.
`--acceptance-sha256` is its independently selected exact lowercase SHA-256;
`--output` must not exist. The writer parses the same bytes it hashes, retains
and rechecks the three allowlisted assets, and repeats attestation verification
before any upload. Only those original three assets can be added. It imports
no product or Forge code and performs no archive extraction. Each upload keeps
the verified bytes in an open anonymous file through `gh --input -`, so replacing
an input path cannot substitute unaccepted bytes at the public write.

The writer checks actual public repository visibility and exact release/tag
identity before upload and on subsequent release observations. Existing equal
assets require unauthenticated public readback without reupload. Newly uploaded
assets require the same size/digest readback. A final state check must preserve
all original and newly verified asset identities. These are observations at
the time of publication; they do not promise that another owner will never
change the release afterward.

Once the writer enters its retained-asset phase, `publication.json` records
`refused_or_partial`, attempted uploads and verified assets if any step fails.
Earlier argument or handoff refusal may occur before that report exists. No
partial result contains a final file inventory, and uploaded assets are not
deleted as rollback. Only complete readback and final checks produce
`status: verified_public_inventory`, the selected acceptance digest, release ID,
tag, original selection and layout, and public wrapper-member URLs with exact
archive/member sizes and hashes. This is the final public URL inventory; an
Actions artifact alone is not that handoff.

## Scope and remaining work

The candidate workflow was checked by source reading, Python AST parsing,
JSON parsing, YAML parsing and exact patch roundtrip. The publication commands
also passed 50 offline controls using controlled verifier results, a controlled
reader and transport responses. Those controls include input substitution,
conflicting assets, partial writes and repository visibility changes. They do
not establish actual signature verification, published Meta-reader acceptance,
public upload or Forge inclusion. No Cargo, packager, native verifier, native
binary, GitHub job or remote host was executed for this draft. Actual attested
candidate inputs and the exact published Meta package must still pass acceptance;
the selected source and input joins need a real owner-authorized CI run.
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
The separate publisher preserves the accepted original bytes, including the
complete indirect producer records, without sanitizing, rebuilding or resigning.
Its presence does not authorize a CI run or publication of the unbound draft.
