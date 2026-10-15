# Source provenance

Public Connect checkpoint IDs recorded below predate a publication-only Git email
metadata rewrite. [PUBLIC-SOURCE-COMMITS.json](PUBLIC-SOURCE-COMMITS.json) maps
them to published commit IDs with identical trees. Names, dates and messages
are unchanged; parent references follow the mapped history. Existing private
Toolkit checkpoint IDs are unaffected. Selected binary, SDK and resource bytes
are unchanged.

This repository is a clean source export from the reviewed Meerkat Toolkit
checkpoint `557c492a78145e223afc5bfa6fcea3e247b8bf4d`, with explicit release
projections. It does not include the private repository's Git history, coordination
messages, captured account data, raw live-case evidence, local build archives or
credentials. The release audit records every included file and projected hash.

Ordinary source tests and their synthetic fixtures are retained. Test certificates,
fixture keys and fixture identifiers are test material, not provider credentials.
Vendor source and third-party notices retain their attribution and license scope.
The unpublished Core codegen source comes from exact Core 0.9.0 revision
`a00bafaf1d862fb41112ff1f30312b350ad05246`; its manifest is projected to the public
dependency layout without changing its implementation source.

## Catalog identity and historical references

The adopted catalog, discovery catalog and frontend catalog preserve their exact
committed bytes and content identities. Some records contain `docs/verification`
or `docs/coordination` locators from the private development repository. Those
records and their historical acceptance data are not part of this public export.
A retained locator is provenance, not a promise of a downloadable public report
or a new live-service qualification.

Do not silently edit a hashed catalog to remove a historical locator. A changed
canonical description requires its corresponding new identity and verification.
Only unused local observation fields are removed from the source-observation
test data; URLs, revisions and recorded source hashes remain unchanged, and the
export audit records that exact projection.

## Distribution boundaries

The root licenses cover original Toolkit code as stated in each component.
The nine extracted HomeCore-derived Python modules are licensed under MIT OR
Apache-2.0 for their Toolkit copies, with exact provenance in
`sdk/python/LICENSE-HomeCore`. This does not change the original HomeCore projects.
Upstream donor notices and optional dependency terms remain alongside their
source and retain their own scope.

A complete native source build, a packaged user distribution, account connectivity
and a completed user task are separate claims. The release notes identify the
accepted artifacts and outcomes. Historical private packaging defaults are not
portable public build prerequisites.

## Selected native packages

The retained CLI packages were built from public Connect
`2656d6777acb0ee1fcdb344fd9e7507aab3ec07b`, with the explicit public dependency
projection. The later `1bb3c234` checkpoint changes only a helper-policy test
fixture. The application gateway correction is public Connect
`52768b64c8e08e576d33f1d893f9401c8eb152ea`. Both matching gateway packages
passed their installed success and resource-corruption checks. It changes
application composition paths that ordinary CLI and stdio setup do not reach. The accepted CLI bytes and their original build
attribution remain unchanged, as do both SDKs and resource inventories.

The public source and macOS build use native registry lock
`9059ad9b7eb38f6869726f0b2c0f1cc7d500f9000ea54eb0ba023f6a46146517`.
The Linux build retains the earlier target projection
`39a9e0f51328aa3083d224cfeae052a39ce8016c8666c767bee7fbd624361825`.
The difference is the already selected `libc` dependency edge added for the
macOS-only store correction. Both projections select the same published Core
and Meta 0.9.0 package identities; their lock files are not byte-identical.

Both platform builds use Rust 1.97.0. macOS uses the optimized release profile;
Linux uses the exercised development profile with debug information disabled.
The selected resource inventories are:

| Platform | SHA-256 of `resources.json` |
| --- | --- |
| macOS arm64 | `cbdc8c838413a732ebe4dbcca5e43da388d1c653beca3cfce102574401b61075` |
| Linux x86_64 | `3280c10bef460edb19dba38099f97a115b7d49856e9dd9a092efa2a9097d5d5d` |

The final package checks use those matching inventories and binaries. They do
not transfer earlier live-account results to new executable bytes. The release
notes retain the actual package, Console and historical development outcomes.

## Included source checkpoints

The timeout and version checkpoint is `88a346721d3d3a78deb39d072151d10c06bac08a`.
Its reviewed timeout correction, fixture prerequisites and 0.9 package metadata
are included. The public dependency projection retains published Core and
Meta 0.9.0 with the exact included Core code generator.

The final licensing metadata checkpoint is
`e02d9a2135b1157f4d4a57e50f966dfa80e092c2`. Its notice and four module-docstring
updates leave the nine module implementations unchanged.

The packaging-only checkpoint
`79b529aff1d91ea45c49870a07c643b7168e3e27` adds the optional release version to
archive names, embedded README commands and checksum companions. It does not
change native implementations, internal prefixes or resource inventories.

The verifier-only checkpoint
`afb1b697b6d834510e56a111c0b016932e4b2e26` opens its selected event-source
fixture component before submitting the event. The existing native admission,
execution and shutdown assertions remain in place.

The application acquisition scope checkpoint
`3aabc80b0c344be4e2868dae370731ee1805da04` separates the canonical acquisition address
from the host-selected deployment used for standing service approval and attachment.
It includes the matching policy guards and focused regression tests.

The macOS store correction checkpoint
`c927f243b1ca2ac9bd69fbc401c683d20c0a491e` uses a one-byte open-description
lock on the same database inode, outside SQLite's lock range. It preserves
publication custody through aliases, clones and entered writes. Other platforms
retain their existing lock mechanism. Toolkit Store alone has one documented
macOS FFI exception to its default unsafe-code denial; the workspace prohibition
for other crates is unchanged. The public registry lock adds its already selected
`libc` dependency without changing any dependency version.

The verifier-only canonical-owner checkpoint
`be682d079b475401f66c683f276923ebc01d968e` makes the installed-product
fixture expect the canonical acquisition address returned by the host. It leaves
the separate deployment, service permission, route and expiry checks unchanged.

The application installation-readback checkpoint
`5cab4f4925bef91d35cdbb4c85120c01eb42b962` is included as clean-public commit
`10fbec40da17c96c61dd5c4045df605a0639993d`. It retains the exact selected software
for application service policies and reopens the typed policy authority for
installation readback. Human approvals keep their existing path; package equality,
parent-policy checks and currentness checks remain required. Historical application
records without the retained software selection are not migrated implicitly.

The captured-consumer guidance checkpoint
`5c01e362b1729a254bff95fd83b5c5328ac9d194` is included as clean-public commit
`c3be3e1d3c87a93f73cf643f03a812f5642c74b3`. After validating the current setup
task and actual tool call, a mismatched consumer selector returns the captured
native member identifier for the agent to submit explicitly. The request still
requires exact equality before access review. No display-name resolution,
automatic substitution or change to raw operation names is introduced.

The test-only diagnostic checkpoint
`69199a3827ae80da0e2c7cf2815e468583cd5d08`, clean-public commit
`9855309b7e218c1026fedcd3eba70667a22972e4`, adds bounded refusal diagnostics to
an existing native control. Its strict currentness assertion and runtime source
remain unchanged. It is not an additional gateway implementation change.

The successor test-only diagnostic checkpoint
`9450d08fbf04f2d236a1a621f97d15a9c8801de2`, clean-public commit
`ebbd8e44113d43128250e0801d35139f0a19323b`, further narrows that diagnostic
without changing production behavior.

The installed-public catalog fixture checkpoint
`acf56a194b10e838b7a0aaba2f38b5e6ab538efc`, clean-public commit
`ea3e0f5c23e495e5d81e46de77bca360c97354ae`, explicitly requests and approves
Original catalog access for the selected package check. It checks the complete
successor policy and actual native search, load and operation results. Other
fixture defaults remain unchanged. This is a verification-source change and does
not modify the gateway binary.

Its verifier successor `2466104c6644bdda636430571dad44ec9e389a65`,
clean-public commit `f1f2c487e6f78f0fc8509b2c1880a3e1e1c785e2`, declares that
standing policy selection explicitly, observes the same SDK exchange with bounded
waits, and requires exactly search, load and one public read in the native result.
The assembler checks those three call identities, arguments and result order.
The gateway binary remains unchanged.

The native audit diagnostic checkpoint
`9617555fac6b0166729712e827ca8db584b1c1d3`, clean-public commit
`07a29bfe79246c1face7393dfaa4bbfdf2bcaa88`, reads existing typed refusal
observations in one native test. It changes no production code or binary.

The package verifier checkpoint `d266fe1d7a39663583d10c209f3a59c49aea1207`,
clean-public commit `60b2751493887a8936f777033f8f93bb1073a70e`, models one
pre-tool controller recovery. Acceptance requires the exact input's persisted
`ReprepareRequired` audit, a distinct successful controller operation, and the
same final search, load and public-read result. It changes no gateway code.

The generic discovery guidance checkpoint is private Toolkit `22f3da82449201b749e1910d1238b8aadff45e98`, projected as public Connect `51a76961c7ff4fcf586f55c220304db1734661b8`. It updates the setup search tool description and installer instructions to explain short public searches, serial operation recovery and candidate-specific failures. The two files are selected library payloads, so the selected product packages require new library/resource digests and matching binaries. These source changes alone do not establish a successful discovery or installation.

The native test-provider correction is private Toolkit `3b63d781b95d066131cd85ecb7f01818178c9a25`, projected as public Connect `ecd46fad0331d9494532e2d5c4a31ce9ca4b01c9`. Two test-only modules now return typed authorization errors through the existing provider contract and advance scripted responses only after authorized output. This preserves Core-owned recovery and exact read assertions; it changes no production binary behavior.

The public-attachment test policy checkpoint is private Toolkit `52fd3307c52db03cb6c43c153ca013f85eb4497d`, projected as public Connect `449dd740252021d235620683a3be30eb9b972085`. The explicit public test variant reviews its one mapped read invocation through the existing complete-policy approval contract. Base fixture grants remain empty; the patch changes only two test modules and does not alter selected resources or production binaries.

The native test-helper compatibility checkpoint is private Toolkit `4cb1a888462786adf5f33289c7a5545227b2ddf8`, projected as public Connect `4656574ce247002944567b693a3cb2591ab185e3`. It restores the existing no-policy helper signature and delegates to the unchanged explicit-policy test implementation. Existing sibling test callers and all production artifacts remain unchanged.

The native human-policy-owner fixture checkpoint is private Toolkit `4d80b350636139fd2ce1922a7f222cd6816766b1`, projected as public Connect `5a9470cefde994245be9bb2b51bf1fcc3282a802`. The fresh public test selects the existing application policy-owner seam before host sharing and retains the exact human-approved full candidate for recovery. Other fixture entrypoints and all production binaries/resources remain unchanged.

The native tool-reprepare test checkpoint is private Toolkit `1882c68bee5086f478e0b780a076102dd2818139`, projected as public Connect `7cd9956966460ae5ef5ed942a9701d4cac3ef71c`. Its synthetic controller may choose one fresh call after operation-local refusal feedback. That candidate incorrectly required the whole refused operation to have no entry observations. Its execution showed enclosing adapter entries before a nested `ReprepareRequired`; the whole-operation non-entry claim is withdrawn. The control stopped before its independent endpoint, cancellation and replay assertions and is not accepted as passing. Attempted operations, enclosing dispatch observations and physical endpoint reads must be distinguished. This changes one test module, not native product behavior.

The layered native tool-audit test checkpoint is private Toolkit `183e3adcf2c052f3a4ec7438ac67aeb5ade2cdfd`, projected as public Connect `55093b2ddda5616667e9d74672ca34c8e92b3647`. It groups observations by exact operation identity while preserving typed refusal, result and controller ordering. The controlled endpoint must record zero reads before the sole fresh choice and exactly one read at completion; existing cancellation and replay checks remain. This corrects the preceding test assumption without changing production code. A later feedback-recovery fixture supersedes this intermediate control, as recorded below.

The setup-research public-search checkpoint is private Toolkit `ffec0982c59b09e0d9805c96f4fd0dd14e96d8c4`, projected as public Connect `bdd87cb1bd20d9a73e9e88bc80e66267c45a85c6`. An exact application policy grant for the dedicated helper can register Core's governed `web_search` tool on fresh and restored helper construction. Other tools, grants and explicit disable choices remain unchanged. This changes native implementation and requires matching binary emission; library, resources and SDK payloads are unchanged. Source review establishes the construction carrier and identity contract, not a successful search. The subsequent fresh Console task offered the tool, but its first call returned `operation_authorization_unavailable`. The task continued through registry research and finished unavailable without installation, access review or data read. The refusal code does not identify which authorization guard refused. Core confirmed separate unsupported stock builtin and nested-model composition seams in 0.9.0; category registration alone was not evidence of usable search. The ordinary MCP successor below removes this experimental selection.

The native feedback-recovery fixture checkpoint is private Toolkit `9ed2d359ac22d44db569da8462502cd580d8445e`, projected as public Connect `2f87a1322ac858521acefc4202af055bc2daffe9`. It follows the exact current input and actual tool feedback across bounded native run recovery, requires zero endpoint reads before any fresh choice and one before the answer, and binds the successful operations to the completed input. Earlier typed failed attempts may span native runs. This changes one test module. The selected native control passed its read-once, replay, cancellation and normal-shutdown assertions against this source. The successful run did not separately serialize its retry count or audit rows, so no particular recovery branch is claimed.

The installed-package startup-budget checkpoint is private Toolkit `013cb2c24c1cae02c8438122403307d2eafcf1c4`, projected as public Connect `e1ca2eed039a751a97f368a46306eefcb88d21e5`. The verifier uses its existing 900-second startup budget for the pre-accepted init request as well as preparation and post-accept settlement. The separate 60-second request default had cancelled two macOS attempts while offline preparation was still progressing; the same CLI preparation completed normally in about 77 seconds. Meta exposes this pre-accept budget as a host configuration choice. Production binaries, resources, ordinary RPC deadlines and all result assertions are unchanged; the affected macOS success and corruption checks passed with the selected host budget. The prior 60-second failures remain distinct, and the earlier Linux success used that stricter bound.

The ordinary public GitHub research checkpoint is private Toolkit `3c3575793e147a61f65d4e378750ab34d9ec2666`, projected as public Connect `2656d6777acb0ee1fcdb344fd9e7507aab3ec07b`. It replaces the experimental native search selection with `setup_search_github` and `setup_read_github` on the existing setup MCP server. The agent chooses public repository queries, document paths and follow-up steps; the host retains exact server configuration, finite operations, normal MCP target lineage and explicit helper grants. The worker uses anonymous direct GitHub API requests and no nested model call. An actual MCP worker proof searched a public repository and read its verified README without credentials. Changed setup payloads require matching library, resource and native binary successors; SDK archive bytes remain unchanged. This worker proof alone does not establish a complete Console task.

The helper-policy fixture checkpoint is private Toolkit `99f07c13db9aa3cde4cf1af33fb912cfee8ea8b4`, projected as public Connect `1bb3c234640ee3c59347c48dbae3ae34a41fbb3c`. It sorts the synthetic grants by their canonical tool names before constructing the test policy. The three new research controls then passed; the six unaffected controls had already passed. Only test code changes, so the selected native implementation remains the preceding `2656d677` checkpoint.

The application helper-projection checkpoint is private Toolkit `6a14bfa4f330988597f13177da7079b085061198`, projected as public Connect `52768b64c8e08e576d33f1d893f9401c8eb152ea`. A fresh Console attempt with the ordinary MCP research grants failed native host composition before login. Its retained preparation had enabled both research operations, while initial Rust compilation retained the base helper profile and server. The later Driver projection added the selected operations, so exact reserved-profile equality refused composition. This cause is derived from the emitted source and retained inputs; the failed process exposed only a generic admission error. The correction selects the policy-derived optional ceiling before capturing the definition, server and resource owner, and checks it against the same compiled policy during completion and restore. Full member, server and definition equality, default-off behavior and runtime policy/currentness remain required. No schema, stored authority, library or SDK payload changes. A dedicated compilation-to-Driver regression reproduced the reserved-profile refusal using the baseline compiler and reconstruction with an extracted unchanged Driver expression and compile scaffold. This was not an untouched all-old product build. The same regression passed on the correction, as did all nine helper controls. Both corrected gateway packages then passed their controlled installed success and resource-corruption checks, including actual catalog search, load, one public read and normal shutdown. Neither corrected run emitted recovery evidence; the prior macOS recovery result remains tied to its earlier binary. These results do not establish the separate real-model Console business journey.
