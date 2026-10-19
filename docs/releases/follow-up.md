# Follow-up scope

The first release retains the complete integration-library and agent-led
acquisition goals while limiting supported deployment breadth.

## Unreleased development progress

An earlier shared-preparation checkpoint used
[Core 95343786](https://github.com/lukacf/meerkat/commit/953437864bbb21b135661a0e61a09b5aa1f6ba01)
and [Meta f04125c4](https://github.com/lukacf/meerkat-meta/commit/f04125c45e732b3ef05aab2ac2a0f642fc1b08a1).
It adds exact preparation membership and retained native/source ownership.
Sixteen earlier owner controls, one SQLite reopen/cancel/complete control and five
focused disposition controls pass. Five additional SQLite workflow controls
cover concurrent joins, replay/reopen, sealing and late delivery obligations.
Six helper admission controls now pass after a meaningful prior-code failure.
The correction retries once only when native policy-change refusal confirms
nonadmission, preserving the same input and deadline. Cancellation, expiry and
uncertain acceptance retain their distinct outcomes.

Four focused SDK feedback controls now pass, including two actual native cases:
one fresh Find after pre-entry refusal creates exactly one acquisition; persistent
refusal stops after two proposals with no acquisition. This is a test-agent
correction, not product retry policy.

Fresh public dedicated reservation and Bind retain their scoped passes, alongside
seven earlier terminal/recovery controls. The public source locator now passes
two SQLite controls and the affected dedicated-member test. Three rebind controls
and one actual second-G-input control also pass. An unchanged test on old
production fails the expected publication-stamp assertion; corrected source is
restored. Healthy admitted-source rebind preserves publication, while new
admission and native currentness checks remain required.

The earlier qualified follow-on includes seven toolkit-mobkit Rust paths and its
guide. A subsequent checkpoint added 14 toolkit-mobkit paths for retained
context transfer and automatic observation, plus a default-off field in the
existing SDK test host. It excludes the unfinished planning fixture chain,
dev-dependency/lock changes and temporary diagnostics.

The shared-workflow qualification report
retains the owner, SQLite, planning-admission, recovery and exact earlier failures.
Planning admission passes on Core `75a23265` / Meta `263ecad4` (r6). The full
shared setup and automatic context-delivery journey remains unqualified.

The selected development consumer uses the same Core with
[Meta r7](https://github.com/lukacf/meerkat-meta/commit/d66f444ef4c4bc50af6a18ac727791aaf21a4541).
It consumes actual SDK/stdio bootstrap completion under the existing host close
boundary and starts the retained recovery owner. Its audit-fixture compile error
is fixed. Three actual runs then failed at different runtime boundaries:

- In one, A's helper reaches installation, but B has no helper tool event. An
  unlabelled ControllerReadinessUnavailable lacks the session and reason needed
  to attribute the failure.
- In the next, both helpers load their catalog, but B's selected check returns
  operation_authorization_unavailable. A's check succeeds.
- In the latest, both checks pass. A's Install returns generic operation_refused
  before the requested cancellation. Native audit and the exact tool sequence
  correlate this with a pre-entry ReprepareRequired refusal. The scripted agent
  rejects the error; the other eight selected cases remain unentered.

All three preserve their failures and pass strict command cleanup. The latest
refusal does not explain the earlier failures, and r7 remains unadopted. Native
Rust retains the typed cause, but the ordinary model-facing error loses the
refusal kind. The Core lead confirms the gap and owns a native feedback correction
for 0.9.4; its reviewed revision is pending. Private audit remains diagnostic
evidence, not a model input or permission to retry an installation.
The Core owner now locates the latest refusal at prepared dispatch after two
successive publication changes, before policy-wrapped staging. The saved trace
cannot tell whether the final change was still in progress. The proposed wait
only applies in that case; it is not yet proof that the next revision fixes this
failure. The next native run must retain the new typed refusal evidence.

A separate admission-recovery gap remains: retaining an uncertain Original does
not schedule recovery. The [reviewed #14 contract](/private/tmp/connect-lead-healthy-watch-pusq5c_i/20261018T225357.132122-claude-gcp-lead-f82ce4.json.txt)
(`e85a4dda`) now fixes the owner obligation. Only a Candidate enrolled in the
source owner's bounded settlement may answer AdmissionPending; unenrolled
candidates, including `retain_unresolved`, remain NotRetained. The owner must
specify its enrollment event, recovery trigger, cadence and step budget, stop and
join settlement and answer no candidate as Pending after close. Every promotion or permanent
withdrawal must announce source-custody change. Promotion requires verified native
admission of the exact input. Withdrawal is terminal across restart, preserves
the uncertain input and binding, prevents resurrection or a fresh duplicate, and
claims no native nonadmission, cancellation or settlement. Unreadable canonical
storage returns Unavailable, never guessed NotRetained or indefinite Pending.
Entered native operations remain separately owned until actual settlement or
close. The exact Core 0.9.4 API revision and Connect's durable-ordering
implementation remain pending; r7 startup alone does not close this gap.

The first preparation/store-binding build failed on two test fixture errors,
before any of its 28 controls ran. The narrow corrections, attempt schema and
foreground persistence now have independent source review and are combined for
one 52-control run. The existing tracked binder persists the exact first input
before Candidate staging; exact retries rebuild current native authentication.
Legacy rows do not acquire invented first-write evidence. Source adoption still
requires the run to pass. Bounded settlement, withdrawal, restart, wake and
stop/join behavior remain subsequent work.

An earlier full SDK diagnostic gets through both helpers' catalog/check calls,
independent approvals, cancellation of A while B installs. Preparation completes
and the original-task script continues once, but B's delivery acknowledgment is
absent. The adapter's Timeout variant does not by itself prove an elapsed timeout.
The combined journey remains failed; its exact admission/reconciliation observations
and cleanup are retained in the report. It does not qualify current r7 behavior.

The installed idle-helper reset and the installed-product positive/resource-corruption
negative are qualified on the r6 development graph. The product case installs an
integration, loads it for the original agent and reads public Hacker News. The
corruption case refuses startup before a setup command. These use a scripted model
with real native execution; they do not establish free-form discovery or account
authentication. The exact evidence and earlier failures remain in the qualification
report. Their two verifier files are checkpointed locally as private `4ecfd6e2`
and public `742f281d`.

Reset after an initialized helper now progresses further. The healthy Initial
correction passes [six actual native controls](/var/folders/9q/3xq99h1s29g68492lry5f3rm0000gn/T/connect-healthy-initial-six-uxxhr5gd/FINAL.json)
with [independent review](/private/tmp/connect-healthy-six-outcome-7unm14pq/REVIEW.json).
It returns custody without repeating the full resource scan during healthy Initial
closure; exact native settlement and validation before every next use remain.
The controls require refusal of changed resources before another spawn and a real
Offered successor after restoring the bytes.

A fresh production gateway (`5b38d2df`) builds and stages with the complete resource
bundle. The [installed reset rerun](/var/folders/9q/3xq99h1s29g68492lry5f3rm0000gn/T/connect-healthy-initialized-reset-n3ijlsh_/FINAL.json)
(`d364b3f7`) runs both old Initial and replacement Offered transports, reaches the
schema tool in both phases, and records four native Begin/Settle completions and a
clean local drain. Initial finish returns within the same logged millisecond;
this is a callback observation, not an isolated benchmark.

The overall reset case still fails: reset and `/console/identities` report the new
helper, while the final `/console/experience` identity and sidebar report the old
helper. The original agent's identity is unchanged. The strict identity assertion
is retained. [Independent outcome review](/private/tmp/connect-healthy-initialized-outcome-tqm912mx/REVIEW.json)
(`9ccdd210`) separates the observed transport success from the skipped final
historical-source and reader/listener checks. The gateway exits normally, its
provider joins and all outer command owners settle. The Meta lead's real-router
probe narrows the cause: the identity runtime and roster already contain the
successor, but the first `/console/experience` read serves a stale cached snapshot.
The planned 0.9.4 fix joins the current identity binding at request time while
preserving visibility and native liveness ownership. The reviewed development
pair is still pending; Connect retains the strict first-read assertion.

The two healthy runtime files are checkpointed locally as private `78721061` and
public `d54c71c9`, after independent review of the six controls and actual native
joins. The initialized-reset verifier remains unadopted until the identity fix
and complete installed pass. Published 0.9.0 assets remain unchanged.

Connect has accepted the Core lead's proposed `DomainBound::OwnedBy` adoption for
0.9.4. Catalog, setup and report/account/public parent grants will bind the actual
application resource authority while retaining exact session/origin children.
Current Connect accepts a supplied application principal but does not establish
that distinct applications receive distinct principals. That contract belongs at
the authenticated installer/activation admission boundary; paths or deployment
labels cannot establish identity. Copies of one application may retain its identity.
A trusted preparation owner may select two distinct authorities for the native
isolation test; no new Core allocator or global registry is required. Two
application instances assigned the same authority are not distinct security
principals. The audit is complete, but the native isolation test has not run.
The cross-application control must exercise two distinct application authorities
in the same native grant domain, including an otherwise valid foreign child
refused as OutsideBounds. New issuance IDs and an explicitly selected preparation
are required; old unrestricted grants and historical children cannot be silently
relabeled or reparented. Python/TypeScript readers preserve native bound objects;
Rust constructor and recovery expectations must migrate together. The actual
Core API, identity contract and migration remain to be qualified.

The Core owner conditionally confirmed an R1 Find-fenced durable transfer commit
as a disclosure boundary, with recipient-only scope and exact payload/reconciliation
checks. Later waiter effects still require that waiter's authority. Three focused
controls pass for retained commit, cancelled delivery observation and stale absence
observation. The automatic recovery path now also passes a control that retains
slow pre-delivery work across dropped polls while another operation proceeds.
The first automatic SDK case now fails before its context assertions; four remain
unentered. The independent r6 planning-admission pass remains separate. This is
implementation progress, not native end-to-end delivery proof.

All six selected native cancellation controls now have passing observations. The
affected rerun checks Core's pre-factory refusal, stale-session refusal and
successful successor attachment. Initial preparation is reusable only after its
exact native cancellation proves no spawn or a normally closed child. Every new
attempt still validates current registration and full resources. The correction
and its tests are checkpointed locally; installed reset remains unqualified.

The durable-input fixture correction retains exact counts and replay checks, now
reached by the passing r6 planning-admission case. Automatic SDK delivery remains
unqualified.

Cold process recovery is separate from retained in-process task ownership.
Acknowledging historical native acceptance requires exact durable evidence,
without restoring operation authority. The Core owner confirms the missing
public query for the internally qualified input key and proposes an additive
0.9.4 API. That query is now available in the development-only
[Core r6 revision](https://github.com/lukacf/meerkat/commit/75a23265f6125f3ce61560ba8388c076a1caccf1),
paired with [Meta r6](https://github.com/lukacf/meerkat-meta/commit/263ecad41260a0b89c5dd0b8caa251164369be22).
Connect's recovery worker now reconciles exact historical acceptance after its
original host closes and the store reopens. An explicit host-selected private
reader and canonical paging find committed records, including workflows created
after startup. A blocked first read does not starve another selected record;
stop prevents new reads and join retains entered work. The query revives no actor,
grants no custody and authorizes no resubmission.

Three earlier controls and 16 affected checks pass with independent review on
this r6 pair. The first three include the real stdio driver reaching native Ready,
retired-recipient admission, store reopening, paging and stop/join. The remaining
checks cover changed envelopes, cancellation and negative historical evidence.
Full canonical transcript/input equality stays intact. The 29 source and
development-graph paths are checkpointed locally at
`af9dfad568a87ba135c4fbf5fa32a1064b357278`. This is component qualification using
host-selected readers and controlled committed uncertain records. An installed
abrupt-process-loss journey and full SDK continuation remain unqualified. Earlier
fixture failures are retained; the corrected checks read the authoritative runtime
snapshot and distinguish controlled source writes from recovery observation.
The supported in-process completion API remains separate. Restoring current
planning authority additionally needs exact host-selected inputs and current
member ownership. The explicit parent-source implementation is adopted locally
with five passing focused controls. The separate two-path delivery claim/retry
correction is adopted locally after four passing actual-store controls. Exact
proven nonadmission survives a definite pre-claim revision conflict; foreign or
older attempts, ambiguous responses and generic Pending/RetrySafe state cannot
supply that proof. Existing recovery owns eventual durable waiter/effect paging and
stop/join; missing evidence cannot authorize resubmission.
Selected setup-agent and caller source restoration now passes seven native
controls on that same r5 graph. After ordinary native resume, the exact selected
inputs regain native custody without resubmission, history changes or model calls.
The setup agent stays restricted and caller effects are not delegated. Foreign,
missing, changed, cancelled and unselected evidence is refused; parent and fresh
planning controls also pass. The 13 source/test paths include two fixture repairs:
separate parent/caller probe capture and actual bootstrap controller-pin wiring.
Earlier failed runs remain recorded. This result qualifies source custody; the
following result extends it to restored workflow interest. Automatic delivery and
a complete process-restart journey remain separate.

Restored interest and the affected recovery controls now pass all 18 distinct
native tests on r5, with independent review. The 16 selected source/test paths are
checkpointed locally at `ace0501abc90babaa60cb1af504f3e0d248dd5ea`.
The original failure compared outer
client Arc identity across repeated pins, while Meta's default wrapper allocates
a new outer client for each pin. Connect now validates exact association, input,
selection, route facts and current ownership inside the protected callback and
retains its exact returned controller. Runnable custody stays on the canonical
source; the workflow retains only route metadata. The tests cover canonical
paging, replay, cancellation, changed membership, retired-agent refusal and
worker stop/join behavior. Seven focused tests and the remaining eleven use the
same compiled source; cleanup assertions and command/transport ownership pass.
The earlier failed diagnostic remains recorded. No new native API was required;
full shared SDK delivery and process-restart completion remain open. The separate
narrow r6 execution above does not extend these r5 interest-restoration results.

The configured Reading frontend has a source-reviewed sender migration and
SQLite connection cleanup. Nine Reading Python tests pass; the separate egress
and sender run passes 299 tests, including real retained-connection closure,
rollback and receipt-preservation assertions. Its actual CLI consumer now stages
successfully but fails native startup with a cleanup wrapper. The gateway's
protocol-rejection wording also covers channel closure after an SDK timeout;
it does not prove a malformed request. The reviewed two-file repair uses the
existing 900-second installed startup bound, retains a 960-second first-phase
observer and preserves typed primary/cleanup causes. Later phases and cleanup
assertions are unchanged. The affected test rebuild passes; the CLI bytes remain
unchanged. A staging-only failure then occurs before native test entry. The
reviewed rerun reuses the previously successful CLI/resource stage while keeping
current test evidence separate from historical staging provenance. The actual
management case now passes in 230.381 seconds: setup exits while the same host
survives, pause/resume delivers queued input once, disable stops queued work and
a pending reply, and removal preserves the same nonempty service state. Three
native admissions occur. Native shutdown is acknowledged; SDK readers and all
application, provider and outer process owners join without escalation. The CLI
includes Core test-support features, and model/provider responses are controlled
loopback fixtures. Independent outcome review accepts the exact pass and cleanup;
the ten-path source composition is checkpointed locally at `58522d73`. This is
development integration evidence. Live provider delivery, native service-tool
authorization and Browser interaction remain unqualified. Earlier build, staging
and startup failures remain recorded. No push, CI or release change occurred.

The installer target is published Core/Meta 0.9.4, with Linux x86_64 qualification
first and macOS arm64 separately. The manual-only
[Linux candidate workflow](../../.github/workflows/connect-candidate.yml) and its
[input contract](../../release/CONNECT-CANDIDATE.md) are checkpointed after
independent source review. It builds Connect's SDK and starter from the selected
source and separates product execution from original-byte attestation. Required
release inputs remain unbound; no CI run or publication is selected. The earlier
r6 rehearsal remains local development
work: original records and embedded host paths are retained explicitly, without
a neutral-provenance or installed-qualification claim.

The candidate acceptance and publication helpers are now checkpointed locally
in public source at `3eb2a7ab`, with independent source and guide review. Fifty
controlled offline tests pass. Acceptance verifies original attested bytes and
uses the selected Meta reader; publication retains those bytes through upload,
checks the selected public repository/release and refuses conflicting assets.
Partial failure retains observations without claiming a complete inventory.
Real attestation, published Meta reader acceptance and public readback remain
unexecuted. These helpers do not authorize CI or publication.

[Source provenance](../../SOURCE-PROVENANCE.md#r5-development-observations)
records the current results separately from adopted source.

The planning-input source is now checkpointed. Seven focused native controls
pass after correcting a binding path that applied the configured helper's root
check to an independently issued planning grant. They cover admission, refusal
of another valid root, lost-reply reconciliation, cancellation and exact
first-producer selection. Five earlier local authority-custody controls also
pass. The original compile and launch failures remain recorded.

Those seven controls admit a real planning input in an existing session; the
later fresh dedicated-member proof above has its own scope. Protected per-waiter
context delivery, operation authority, shared SDK completion, gateway/reset and
remote restart remain open.

Workflow cancellation now retains cleanup after the cancelling caller returns.
All 12 selected native/store controls pass, covering cancellation racing a queued
join, independent membership, exact close reconciliation, lost local handles and
recovery through the existing worker. Five Python and five TypeScript adapter
controls also pass. The SDKs expose durable cancellation with cleanup pending;
consumers need matching SDK generations because older decoders reject that state.
Three earlier build failures remain recorded. Terminal-result/expiry departure
has the separate focused passes above; active planning-input shutdown and the
complete shared journey remain open.
[Source provenance](../../SOURCE-PROVENANCE.md#shared-preparation-and-source-owner-currentness-work-in-progress)
records the precise scope. Published 0.9.0 assets remain unchanged.

Explicit Node builds now use agent-authored commands and a host-selected toolchain
through the existing installation review, job and readback. Thirty-seven distinct
focused controls pass. A real Linux x64/glibc 2.39 case compiled a native addon with
Node 24.19.0 (ABI 137); a fresh consumer loaded it and returned 42 for 19 + 23.
Original installer output binds the receipt, replay reuses the checked job and
inert readback preserves the installed files. Three earlier fixture failures are
retained. A later matching installed product also completes a supplied source-built
MCP case: the helper checks, installs and reconciles the exact build; protected
software/access decisions lead to one native Original `source_add` call and its
actual result 42. Native completion, two displayed leaf revokes and recorded
physical cleanup passed independent review. This uses a controlled model schedule and synthetic package. General npm
compatibility, autonomous choice, Browser UX and hermeticity remain open. See
[source provenance](../../SOURCE-PROVENANCE.md#installed-source-built-mcp-operation).

Selected Python/Node installer cancellation now gives the pinned installer time to join its direct child before outer escalation. It retains partial output and the original unconfirmed job for observation; exact replay does not start another install. Fourteen new and six retained controls passed. This qualifies the cancellation and direct-child boundary, not npm/compiler/package execution or arbitrary descendant cleanup.

[Source provenance](../../SOURCE-PROVENANCE.md#selected-installer-cancellation) records the validation scope. Released 0.9.0 assets remain unchanged.

Local setup now keeps the protocol child in its original preparation owner
across errors and offers a move-owned asynchronous guard. Existing CLI calls
remain compatible; borrowed guard Drop requests cancellation while retaining the
handle needed for an explicit join. Seven focused controls pass on the current
Core/Meta graph, including cancellation, malformed replies, changed resources and
that same-child join. The initial fixture failure remains recorded.

This qualifies synthetic process custody. Native adapter, gateway/reset and
shared SDK acceptance remain separate, as does CLI recovery after a persistent
OS wait error. [Source provenance](../../SOURCE-PROVENANCE.md#retained-local-setup-process)
records the exact checkpoint and limits. Released 0.9.0 assets are unchanged.

An installed controlled Console API case now completes repeated acquisition in
one Original session. It first installs and uses Hacker News, requests Wikipedia
through the same surviving helper, then answers using both services. The earlier
Hacker News job is reused without reinstalling it; the new continuation receives
fresh grants for the complete service set. All three Original runs and both
helper runs complete. Exactly five displayed service/catalog grants are revoked,
login retirement is certain and native/process owners join.

This case uses a controlled model schedule with real native execution and public
service calls. It qualifies installed continuation and reuse, not autonomous
integration choice, Browser interaction, helper reset, process restart,
authenticated batches or concurrent shared setup. No controller-recovery notice
occurred, so the new recovery validator has source/control evidence only.
Separately issued setup children and persistent policy are outside the five
displayed revokes. Published 0.9.0 assets and requirement statuses are unchanged.

[Source provenance](../../SOURCE-PROVENANCE.md#installed-repeat-acquisition) records exact versions and evidence.

The fresh V40 journey now completes agent-led discovery of an outside-catalog
integration, protected installation/access and the original business answer
through the controlled Console API. The same Original reported overdue invoices
rising from EUR 2,900 to EUR 4,600, a EUR 1,700 increase led by Linden Works at
EUR 1,300. Independent recomputation confirms all figures and strict cutoff
handling. The question was submitted once, without operator follow-ups, direct
business calls or manual wakes.

V40 used exact public `1779df8f` with ordinary Forge generation and no overlays
or recovery selection. The task grant is unavailable after protected revocation;
logout, local session removal, normal Stop and physical cleanup passed independent
review. Owned sessions/forwards are joined and ledger/sidecar identities unchanged.
This qualifies the controlled API journey, not Browser/UI completion, installed
recovery or independent runtime write prevention. Published Connect 0.9.0 binaries
are unchanged. [Source provenance](../../SOURCE-PROVENANCE.md#unreleased-follow-up-source)
retains exact source identities, earlier failures and scoped validation.

Development source now supports 2-8 public MCP services in one acquisition.
The agent chooses the checked installation jobs and operations. One protected
access review covers the exact set; each service has separate grants and must
become natively usable before one continuation answers the original question.
Software installation keeps its existing reviews. Separately reviewed agent tool
permissions last until superseded and do not replace exact task grants. See the
[Console guide](../site/guides/request-an-integration.mdx#use-several-public-services-in-one-console-task-development).

Twenty-nine distinct Rust controls pass (21 focused and eight native). Restoration
coverage is settled historical source custody, not process restart or a new
post-restoration operation. The earlier fixture-order and public-refusal
classification failures remain recorded. The panel passes 48 JavaScript controls,
including visible per-service operations, deadlines,
remote endpoints and policy scope. A fresh controlled Console API case on public
`4fb67218` selected and installed both services after correcting the initial
provider route through normal setup. It made no receipt reconciliation call;
three public requests returned generic unavailability before access review.
Current library metadata was also absent because help was read before checking.
No service grant, business call or final answer resulted. Logout, normal Stop and
exact physical cleanup are independently closed. The feedback repair now passes
four focused controls; restoring only the old generic mapping makes the unchanged
correction regression fail at runtime. Agents can see the existing reconciliation
and fresh-help requirements.

V43 now completes the ordinary two-service case on public `be0df64c`. One business
request names Hacker News and English Wikipedia, without preselecting integration
IDs, profiles or strategies. The agent chooses and reconciles two installation
jobs, obtains one exact complete-set access decision, and the same Original
automatically uses both services and answers. Three exact task-grant revocations,
logout, normal Stop and physical owner cleanup pass independent review. The
separately reviewed policy successor remains until superseded.

The four-proof join with V40 and the native authority controls closes SETUP-002
for the declared development profiles. Story 2's Wikipedia relevance remains
explicitly uncertain; technically successful tools do not guarantee semantic
perfection. V41 remains failed before access, and V42 remains a failed, uninstalled
Build whose generated callback contract would have required new policy grants.
The policy was not widened. V43 uses a normal source-preserving refresh of the
accepted neutral application, with a fresh installation and native namespace.
Browser interaction, authenticated batches and warm later acquisition remain
separate. Other requirement statuses and released 0.9.0 artifacts are unchanged.

Development warm reacquisition now passes 28 distinct Rust and 49 JavaScript
controls. A host-selected configured capability lets the continued task use the
same live helper for a later public acquisition. The new review covers fresh
setup and service grants plus metadata access for both named agents across both
named sessions. The helper can select a current earlier job together with a new
job, but all grants for the next continued task are fresh. Native Ready and
independent-target checks, stale policy and recovery refusals, and checked-job
reuse pass; earlier R1-R5 fixture failures remain retained. All command owners
joined. See [host composition](../site/guides/host-composition.mdx#acquire-another-public-service-through-the-same-live-helper-development)
and [source provenance](../../SOURCE-PROVENANCE.md#warm-public-reacquisition).
Helper reset, Browser behavior and performance remain unqualified.
Requirement statuses and released artifacts are unchanged.

The first strict installed check on public `63c8d79a` failed after software
installation and receipt reconciliation. Its valid legacy profile gives the
Original and helper different audiences. Warm selection incorrectly compared
helper targets with the Original audience and returned a policy refusal before
public access review. The corruption case was not entered, and no Forge app or
business question was started. Normal native shutdown and physical cleanup
completed. This is a Connect compatibility regression, not a missing policy grant;
the failed execution remains retained.

The scoped correction validates targets against the actual helper audience,
then preserves legacy fallback for initially ineligible configurations. Seven
affected Rust controls pass, including actual cross-audience public preparation,
captured-scope refusal, partial recovery and both native repeat-acquisition cases.
Six are existing controls; the cross-audience control is new. Restoring only
the old production comparison compiles, then fails that new test at actual public
preparation with Conflict. No permissions or installed assertions were relaxed.

The fresh production gateway from public `3ecf0d5a` now passes the unchanged
strict installed success and resource-corruption pair. The success case reaches
the actual continued agent's durable consumed/completed receipt; corruption
refuses before negotiated entry. Native shutdown, readers, providers, children,
process groups and the build lock all settle. Independent review verifies the
exact source and artifact bindings. The gateway build retains 65 warning headers.
This closes the installed compatibility regression. The later R9 case
separately qualifies installed repeat acquisition.

V44 then completes an initial setup-enabled two-service batch through the
controlled Console API on that corrected production source. The host's actual
catalog/audience profile is eligible, but both services are selected up front,
so V44 alone does not establish B-to-C or retained-X reuse. Six tool errors recover
automatically before the Original answer. Exactly three displayed service/catalog
grants are revoked and physical cleanup joins all owners. Those revokes do not
cover separately issued setup children or reverse the persistent policy. See
[source provenance](../../SOURCE-PROVENANCE.md#v44-initial-setup-enabled-batch)
for the exact final evidence and answer limits. No additional requirement closes.

Concurrent shared setup remains in development and is not covered by this
installed repeat-acquisition result.

- **Bounded setup-job observation:** Development `setup_job` accepts optional
  integer `wait_ms` from 0 to 10000; omitted or zero keeps the immediate response.
  Cancelling the observation leaves installation running, and explicit stop stays
  separate. Eight Python and four Rust controls pass for exact-job custody and
  observation lifetime. V44 uses seven actual `wait_ms: 10000` requests during
  its completed initial batch. This establishes usage without a comparable
  latency claim, shared-peer isolation or readiness.
  See [source provenance](../../SOURCE-PROVENANCE.md#bounded-setup-job-observation).
- **External Agent Plugins consumption:** A format-adapted Microsoft
  `microsoft-docs` 0.3.1 pack now exports on Linux and runs through unchanged
  OpenHands SDK 1.49.2 on macOS. After staging removal, all eight original files
  and two canonical JSON values match; the actual client loads three skills and
  fetches a substantive 2,089-byte Azure Blob Storage overview with one tool call.
  Independent outcome review and natural local cleanup pass. Both earlier UMT
  initialization failures remain failed with zero tool calls. See the
  [portability example](../site/reference/portability.mdx#qualified-external-client-example)
  for the explicit format adaptation and limits. An independent four-proof audit
  now closes PKG-007 for the declared canonical Agent Plugins 1.0 skill/MCP
  import/export subset, including required-contract and malformed-entry refusals.
  D3 and PKG-006 remain open.
- **Retained approval recovery:** Development now includes one bounded inventory
  of existing parent/access/source records and reviewed exact cleanup through the
  existing native owner. Explicit Console operator policy requires the retained
  human plus current admin/member/login authority; independent local OS-operator
  SDK selection supports the inherited terminal's `/recover` command. Published
  sources and other approvals are preserved, and absent-parent or partial effects
  remain unresolved. Policy observation stays separate. The repaired UI suite
  passes 40 controls; a reviewed selector map joins 26 distinct passing Rust
  controls across native/SQLite, SDK, terminal and actual-verifier behavior. The fixture uses native
  identity restoration after actual HTTP diagnostics confirmed a stale alias.
  Inherited PTY adoption uses `O_NOCTTY`, with an isolated session-leader control.
  Earlier failed runs remain recorded. See the [host guide](../site/guides/host-composition.mdx#recover-unpublished-service-approvals)
  for explicit selection and use. A separate ordinary development Rust SDK consumer
  now reopens the same installed host after fixture preparation and owner closure.
  One public API recovery action revokes unpublished B's parent/child, preserving
  published A, canonical source rows and native input history. Exact journal
  readback and natural cleanup pass independent review. The first producer
  duplicate-admission failure remains failed; its repair preserves the unchanged
  consumer, authority and deadline. This is pre-agent SDK consumption, not a
  released distribution, stock gateway, terminal, Ready or real-crash proof.
  Browser login remains open; V40 excludes these changes. No standalone realm
  recovery command or automatic startup revoke is added. Forge/MobkitInstaller's optional
  selection and cold-controller pin correction passes 38 reviewed controls but
  has no installed adoption claim and changes no generator default.
- **Approval failure cleanup:** After an approval worker joins with an error,
  the source owner reconciles the exact result and attempts unpublished-grant
  revocation. Native refusal or uncertainty remains unresolved. An already
  published exact source and another approval's child are preserved; late
  publication rechecks grant eligibility. Seven focused native/SQLite tests pass,
  and the prior approval body fails the missing-revocations assertion with the
  same fixtures. Independent source and execution review passed. This covers
  returned errors, not process loss, cold recovery or installed Console behavior.
  Login uncertainty remains retained and policy is not rolled back. Historical
  failed-case cleanup remains independently verified; V40
  completes the separate original business answer.
- **Review expiry:** Console and terminal reviews continue polling their existing
  deadline while displayed. Focused checks and an actual expired Console review
  confirm settlement without extending approval lifetimes or changing authority.
- **Bounded status observations:** A stalled status read now expires after 30
  seconds across headers and body, aborting only that read and restoring explicit
  First-page recovery. Late results cannot replace the current view. All 45
  JavaScript controls pass; three prior-source regressions fail as expected. A
  real Node loopback check confirms both held requests close before teardown and
  a fresh read succeeds. Protected actions and their polling fence are unchanged.
  This is component/Node transport evidence, not Browser interaction, native
  effect completion or full UX-002 qualification.
- **Protected action ordering:** Panel reads pause while this document has a
  protected action pending, then refresh current state after settlement. The
  access endpoint's stale-offer 409 now reports definite nonentry without retrying
  the mutation. Two prior-source regressions and 36 controlled JavaScript checks
  pass with independent review. Other tabs can still replace an offer; this adds
  no cross-tab lock or claim that observation timeout cancels an action. V40
  includes these bytes and completes protected API actions. The official hidden in-app Browser was
  unavailable before any tab, read or UI action in a separate synthetic-transport
  fixture. The fixture stopped naturally with joined owners; no mouse or
  substitute driver was used. Actual Browser interaction remains unqualified.
- **Operation feedback:** Public and declared-secret-slot requests identify exact
  permitted raw tool names when a current checked selection receives invalid
  names. A controlled Console test now exercises the invalid-name feedback before
  credential review.
- **Usable permission proposals:** The Console fallback for a waiting original
  task rejects missing catalog scope or selected-tool coverage before protected
  review. Approval still covers the complete successor member policy until
  superseded and eligible catalog metadata throughout the original conversation.
  This explicit selection supplies the new task's catalog authority even when
  ordinary policy already permits the tools. Grants remain separately scoped and
  finite; trusted application delegation and lower-level APIs are unchanged.
- **Explicit helper catalog successors:** A new host opt-in retains a separate
  catalog-read-only parent and derives a child for the actual native helper
  session. Omitted scope retains the existing captured-session behavior. Existing
  grants and retained work keep their original bounds and targets. Source review
  passed, and 57 distinct focused controls now pass, including an actual native
  helper reset. The reset control contrasts legacy authorization refusal with
  authorized Search and Load in explicit successor mode. The inline-only test
  operation still returns `not_deferred_eligible`; this proves catalog
  authorization, not successful deferred loading. Host-adapter source checks
  passed separately, without installed successor qualification. See the
  [host guide](../site/guides/host-composition.mdx#helper-catalog-access-after-reset).
- **Target-bound npm dependencies:** Supported optional dependency graphs retain
  the full lock and archives while selecting compatible packages for the exact
  target. A pinned Linux `chokidar-cli@3.0.0` installation, performed offline with
  lifecycle scripts disabled, produced a fresh file event. Optional peers and
  arbitrary native payloads remain out of scope; this run qualifies Linux only.
- **Portable executables:** Explicitly included Unix scripts retain executable
  intent through export without copying unsafe mode bits or widening the caller's
  umask. Inspection detects permission drift even when bytes are unchanged and
  keeps historical unrecorded mode observations distinct. Eighteen focused
  controls pass, including use through a generic stdio client after source
  removal. Strict Clippy remains limited by two documented existing lint categories;
  scoped Clippy passes with command-only exceptions. This does not qualify
  third-party packages, Windows permissions or complete Agent Plugins support.
- **Discoverable plugin guidance:** The existing inspection tool can list one
  bounded package directory, letting an agent find unfamiliar skill and reference
  names before choosing explicit text reads. Inventory carries no source custody
  or execution authority. Eleven macOS Rust controls, 34 focused Python controls
  and one real MCP/canonical-reader recovery test pass. The latter uses a scripted
  client and inert installer, and recovers the same selected text after staging
  removal. Independent review passed. Linux's non-UTF8 fixture control remains
  unexecuted; scoped Clippy retains one existing lint exception. Installed-host
  and full package interoperability qualification remain separate.
- **Fresh recovery proposals:** `find_and_install` guidance permits a new reviewed
  proposal within the original request and current authority after a failed
  attempt. It does not require another chat authorization solely because setup
  failed, permit approval replay or force repeated attempts. Software and access
  reviews remain required. Retained failure payloads stay unchanged for delivery
  reconciliation. A fresh Console run demonstrated an autonomous new proposal
  with this guidance delivered, without establishing wording-only causality.
- **Retained failure feedback:** The existing source cancellation, replay and
  continuation path retains a bounded startup phase, fixed failure class and
  optional closed-process exit. The first committed observation remains immutable;
  delivery checks the exact source before resuming the original agent. Stage 2
  now reads optional metadata from the exact native attempt under the remaining
  readiness deadline. Missing or late metadata preserves a timely failure and
  legacy bytes. Five distinct controls pass, combining four retained scripted
  results with one corrected actual native initialize-failure control. The same
  actual native fixture reproduces missing capture on old production source;
  independent review confirmed the outcomes and joined cleanup. The earlier 12
  synthetic controls and valid old-reader regression remain recorded, along with
  fixture failures and scoped lint/format limitations. Raw stderr and arbitrary
  server messages are excluded. The latest controlled Console case now delivers
  an actual initialize/closed/code1 observation to the original agent before its
  fresh reviewed proposal. That installed observation does not establish
  historical failure causation or successful business recovery.
- **Startup recovery guidance:** After a known startup or attachment failure, guidance
  asks the agent to inspect the failed closure's relevant imports and startup API
  calls, then inspect those same edges in the exact acquired replacement before
  proposing installation. Both the standalone prompt and existing inspection-tool
  description carry it, preserving the integrated helper's host profile. Source
  review and AST comparison confirm unchanged schema, dispatch and authority. No
  package pins or capabilities are added. V40 consumes the refreshed package and
  completes original-task use; it does not isolate this guidance as the sole cause.
- **Approved-service continuation context:** A committed correction adds a
  checked attachment observation, approved operations and effective expiry to
  the existing native injected-context slot. The original reviewed question is
  unchanged; native authorization and exact-input replay keep their existing owners.
  Four focused native controls and independent source/execution review pass.
  The prior-projection comparison retains additive fixture-compatibility metadata
  and fails after native admission at missing-context assertions. The initial
  missing-import compile failure remains recorded. Restoration covers source
  custody, not full process restart. The observation promises neither future
  readiness nor filesystem isolation. The corrected package now completes a
  controlled installed SDK public read with exact native input completion and
  rejects resource corruption before model entry. Its first installed run failed
  an obsolete fixture predicate; a strict fixture-only repair reran the same
  product bytes successfully. Both cases exited naturally with joined cleanup.
  An untagged Meta transport-reader diagnostic remains recorded. V39 then failed
  both attachments before the context path. V40 now completes automatic
  same-Original business use; Browser UX remains unqualified.
- **Research across setup helpers:** A fresh normal helper can inspect an
  explicitly host-selected prior acquisition after exact matched reconciliation.
  Its historical status stays unconfirmed, and current owner, profile, runtime
  and retained-file checks remain required. One old-source regression and 34
  passing local controls include actual MCP inspection with fixture archives.
  This does not replay installation or qualify automatic cross-helper import,
  installed-host adoption or the complete business recovery journey. See the
  [inspection guide](../../sdk/consumer-setup/ACQUIRED-INSPECTION.md#custody-and-limits).
- **Retained guidance export:** The saved-recipe CLI exports explicitly selected
  public skill files after staging removal. It checks exact ownership, identity,
  source and paths, preserves plugin namespaces and requirements, and adds no MCP
  configuration, activation or execute bits. The corrected final source compiled
  and passed 24 focused macOS controls, including retained SQLite source,
  fresh-process export/readback and independent file-reader use. Three old-source
  runtime failures remain retained. Review rejected a duplicate-import formatting
  candidate; the corrected source was recompiled and retested. Changed-region
  formatting and scoped Clippy pass with one existing lint exception. Installed
  adoption and full package interoperability remain separate work. See the
  [operator guide](../../crates/toolkit-package/LOCAL-RECIPES.md#export-selected-retained-guidance).
- **Independent application roles:** A persistent Reading-host test confirms that
  the same exported service and store remain usable after frontend removal and
  management-CLI exit. Existing admission, reply and shutdown checks also pass.
  This establishes application service survival, not native service-grant or
  model-dispatch qualification, live frontend adoption or restart coverage.
- **Closed frontend senders:** New local deliveries stop before provider cleanup
  is awaited. Per-sender lifecycle serialization preserves independent senders,
  replacement attachments, durable owner selection, pending output and receipts
  from calls already in progress. Independent review and 198 affected tests pass,
  including a two-authority activation race and failure/cancellation cases. A
  separate, independently reviewed installed Python SDK consumer now qualifies
  two inert senders: A detaches before cleanup, entered work keeps its receipt,
  pending work spends no attempts, and B remains usable. The same nonempty Reading
  service fixture, store, export and database bytes stay unchanged; all owned
  tasks and the process are joined. Two fixture-only preparation refusals remain
  recorded. Actual HomeCore or Reading frontend adoption and live provider
  delivery remain pending.
- **Supplied schema evidence:** The optional metadata inspector computes a digest
  of exact supplied JSON bytes and rejects malformed or oversized input within
  the caller's existing permission ceiling. Its 20 Python checks and one native
  permission check pass. The matching Linux package also passes the installed
  success/corruption pair, including an actual controlled helper invocation after
  native catalog loading. A fresh free-form helper also used it successfully.
  This qualifies supplied-byte hashing, not runtime observation, schema
  validation, readiness or completed business use.

The previously assembled development package passed gateway assembly, controlled
installed success/corruption checks and fresh Console startup. Its focused
permission checks include native catalog loading and a mapped inert invocation.
Those results predate the new helper catalog successor source and do not qualify
that mode or a completed real-model business journey.

A controlled Console API test completed protected credential submission,
attachment and one authenticated GitHub account read by the same original agent.
Its task grant was revoked and application processes were closed. The new
`credentials status` and `credentials remove` commands passed 20 focused controls
and actual same-store `Stored` -> protected removal -> `NotStored` checks using
the normally emitted development CLI. Removal preserved service configuration
and grants without a model, setup helper or another credential fetch or account
read. This resolves local credential cleanup, not provider-token revocation or
full browser-UX and free-form discovery qualification.

Earlier operator-invalid runs, reset/catalog refusal, V37 attachment failures,
V38's missing-context answer failure and V39's initialize failures remain failed
and closed in [source provenance](../../SOURCE-PROVENANCE.md). V39's later exact
unpublished-grant cleanup is distinct from product recovery. V40 does not
reclassify those cases or prove their initialization causes. Paired native
setup-launch ownership and explicitly selected installed recovery remain separate
owner-coordinated work.

D3 also retains bounded Linux prebuilt native-addon load/read/write-refusal.
V40 adds real native-addon MCP acquisition, installation and original-task use:
`@database-mcp/sqlite` 0.4.2 / `better-sqlite3` 12.11.1 on Linux x64/glibc 2.39,
Node 24.19.0 ABI 137. Independent review matched the 135-file acquisition inventory, exact installed addon, primary entrypoint
and runtime to the recorded adapter calls and answer, without a new business probe.
Portable import with host-mediated same-session continuation and declared
Compose owner-conversion evidence on macOS and Linux also remain qualified. These are narrower than
general native compilation or accepted native application-profile migration.
The Microsoft/OpenHands case above adds one real, format-adapted Agent Plugins
client operation. PKG-007 is complete for the declared canonical skill/MCP
subset; additional client/format profiles remain unqualified. The saved-guidance export above
already closes the earlier retained-file export gap; no repeat of that proof is
needed. PKG-006 and the remaining D3 breadth stay open.

## Released 0.9.0 limits

| Area | Practical limit in 0.9.0 |
| --- | --- |
| Frontends and custom extensions | Source components and role contracts remain available for explicit host adoption. There is no general Telegram, Slack frontend, HomeCore, Reachy or OB3 migration promise. A persistent application must own identity, audience, routing and delivery. |
| Existing application upgrades | Application host support is scoped to fresh composition. Updating an existing application's selected gateway requires the host's replacement-selection wiring; automatic upgrade across arbitrary hosts remains follow-up work. If Fresh startup fails before producing completed setup and its finalizer, same-installation Restore/update has no admissible completion or replacement envelope. Preserve that failed installation and use the normal fresh path with an empty sibling target. |
| Forge-generated Console | The preserved-design refresh failed acceptance before Install and the original question. Forge must honor an explicit no-account-request brief in the initial helper policy, and omit unsupported optional analyst edges and delegation text while keeping peer tools denied. Complete fresh real-model task acceptance remains unproven. |
| Predecessor application stores | Adoption of an existing nonempty MobKit 0.8 store under authoritative Meta 0.9 startup is deferred when its composition manifest has only the legacy `created_by_mobkit` writer field. Fresh Meta 0.9 Console installations and Core realm/session CLI use are separate paths. |
| Provider onboarding | Some providers require an existing application, administrator consent or native credential. Universal registration and every remote/mobile/headless auth transport are not included. |
| Package formats and updates | Supported profiles and dependency closures are explicit. Arbitrary native addons, all MCPB/platform combinations and seamless migration or rollback are not promised. |
| Provider operations | Support covers declared operations and account profiles. It is not certification of every upstream API, MCP feature or end-to-end business workflow. |
| Remote deployment and shared workflows | Cloud/GitOps rollout, every durable store and broad unattended multi-user orchestration remain application-owned adoption work. |
| Live devices and modalities | Robot, voice, media and physical behavior need separate application and hardware acceptance. |
| Management and accessibility | Additional management parity, client modes, accessibility coverage and performance measurements require their own evidence. |
| Startup diagnostics | Native admission currently exposes a generic composition refusal. Preserve and present the inner Connect composition error through a safe diagnostic channel so application owners can locate configuration conflicts without a separate source trace. |

These limits do not permit broader grants, guessed accounts, hidden service
retries or claims that a configured frontend is running. Unsupported combinations
must report their missing requirement before performing the privileged effect.
