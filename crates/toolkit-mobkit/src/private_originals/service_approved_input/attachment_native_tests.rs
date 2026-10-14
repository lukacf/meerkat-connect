//! The production caller enters native from an empty keeper. Only model IO
//! and installed-package readback use mechanical fixtures. The stdio MCP
//! process, native Apply, accepted receipt and operation observation are real.
use super::super::super::admission_tests::{approve_b_configuration, approve_b_configuration_with_tool_policy};
use super::*;
use futures::StreamExt;
use meerkat_authorization_contracts::work_association::InputAuthorityAssociation;
use meerkat_core::{
    ApprovalDecision, ApprovalRecord, ApprovalStatus, ControllerModelSelection, Message,
    Provider, StopReason, ToolIdentity, ToolResult, lifecycle::InputId, types::ToolSourceKind,
};
use meerkat_llm_core::{
    LlmClient, LlmDoneOutcome, LlmError, LlmEvent, LlmRequest, LlmStream, PlainModelRoute,
    PreparedLlmRequest,
};
use meerkat_runtime::completion::CompletionOutcome;
use meerkat_runtime::terminal_status::{InputTerminalReceiptRead, InteractionSelector};
use meerkat_runtime::input_state::{InputLifecycleState, InputTerminalOutcome, StoredInputState};
use meerkat_runtime::{LogicalRuntimeId, RuntimeStore};
use std::{path::{Path, PathBuf}, sync::atomic::AtomicBool};

type PersistentFixture =
    ContinuationFixture<meerkat::PersistentSessionService<meerkat::FactoryAgentBuilder>>;

struct Endpoint {
    _directory: tempfile::TempDir,
    started: PathBuf,
    listed: PathBuf,
    released: PathBuf,
    called: PathBuf,
    result: String,
}
impl Endpoint {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        Self {
            started: directory.path().join("started"),
            listed: directory.path().join("listed"),
            released: directory.path().join("released"),
            called: directory.path().join("called"),
            result: format!("public-read-{}", uuid::Uuid::new_v4()),
            _directory: directory,
        }
    }
    fn config(&self, realm: &str) -> meerkat_core::McpServerConfig {
        // The existing native fixture uses this same line-oriented protocol.
        // Positional arguments keep temporary paths out of shell source.
        let script = r#"printf 'start\n' >> "$1"
while IFS= read -r line; do
  id=$(printf '%s\n' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"toolkit-test","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf 'list\n' >> "$2"
      while [ ! -e "$3" ]; do sleep 0.02; done
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"read","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"method":"tools/call"'*)
      printf '%s\n' "$line" >> "$4"
      case "$line" in
        *'"name":"read"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"%s"}],"isError":false}}\n' "$id" "$5" ;;
        *) printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"unexpected fixture operation"}],"isError":true}}\n' "$id" ;;
      esac ;;
  esac
done"#;
        let mut config = reviewed_config_operations(realm, &[Id::new("read").unwrap()].into());
        let connector = config.connector.take();
        let mut config = meerkat_core::McpServerConfig::stdio(
            "mail",
            "/bin/sh",
            vec![
                "-c".into(),
                script.into(),
                "toolkit-attachment-fixture".into(),
                self.started.to_str().unwrap().into(),
                self.listed.to_str().unwrap().into(),
                self.released.to_str().unwrap().into(),
                self.called.to_str().unwrap().into(),
                self.result.clone(),
            ],
            Default::default(),
        );
        config.connector = connector;
        config
    }
    fn release(&self) {
        std::fs::write(&self.released, b"release\n").unwrap();
    }
    fn starts(&self) -> usize {
        match std::fs::read_to_string(&self.started) {
            Ok(text) => text.lines().count(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => panic!("fixture process observation failed: {error}"),
        }
    }
    fn calls(&self) -> Vec<serde_json::Value> {
        match std::fs::read_to_string(&self.called) {
            Ok(text) => text.lines().map(|line| serde_json::from_str(line).unwrap()).collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(error) => panic!("fixture invocation observation failed: {error}"),
        }
    }
    async fn wait_for(&self, path: &Path) {
        tokio::time::timeout(WAIT, async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("actual local MCP phase was not observed");
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        // Panic cleanup releases a tools/list barrier before native shutdown.
        // This is a fixture transport signal, never an authorization decision.
        let _ = std::fs::write(&self.released, b"release\n");
    }
}

const PUBLIC_READ_CALL: &str = "actual-public-attachment-read";

#[derive(Default)]
struct PublicReadScript {
    armed: AtomicBool,
    responses: AtomicUsize,
    expected_instruction: Mutex<Option<String>>,
    offered: Mutex<Option<ToolIdentity>>,
    feedback: Mutex<Option<ToolResult>>,
}
impl PublicReadScript {
    fn provider(self: &Arc<Self>, inner: Arc<dyn LlmClient>) -> Arc<dyn LlmClient> {
        Arc::new(PublicReadProvider { inner, script: self.clone() })
    }
    fn arm(&self, instruction: String) {
        assert!(!instruction.is_empty());
        assert!(self.expected_instruction.lock().unwrap().replace(instruction).is_none());
        assert!(!self.armed.swap(true, Ordering::SeqCst));
    }
}

struct PublicReadProvider {
    inner: Arc<dyn LlmClient>,
    script: Arc<PublicReadScript>,
}
#[async_trait::async_trait]
impl LlmClient for PublicReadProvider {
    async fn prepare_controller_credential(&self) -> Result<(), meerkat_core::auth::AuthError> {
        self.inner.prepare_controller_credential().await
    }
    fn plain_model_route(
        &self, model: &str,
    ) -> Result<PlainModelRoute, meerkat_core::ControllerFactsUnavailable> {
        self.inner.plain_model_route(model)
    }
    fn controller_model_selection(&self) -> Option<ControllerModelSelection> {
        self.inner.controller_model_selection()
    }
    fn project_replay_messages(&self, messages: &[Message]) -> Result<Vec<Message>, LlmError> {
        self.inner.project_replay_messages(messages)
    }
    fn stream<'a>(&'a self, request: &'a LlmRequest) -> LlmStream<'a> {
        self.inner.stream(request)
    }
    fn stream_prepared<'a>(&'a self, request: &'a PreparedLlmRequest) -> LlmStream<'a> {
        // This retains the existing provider's native model authorization,
        // physical-entry observation and request count for every response.
        let stream = self.inner.stream_prepared(request);
        if !self.script.armed.load(Ordering::SeqCst) {
            return stream;
        }
        // A refused prepared operation is not a scripted model response.
        // Advance only after the inner provider yields authorized output so
        // Core recovery cannot consume or replay the one public read.
        let mut response = None;
        Box::pin(stream.map(move |event| event.map(|event| match event {
            LlmEvent::TextDelta { meta, .. } => {
                assert!(response.is_none(), "one authorized response must have one text delta");
                let selected = self.script.responses.fetch_add(1, Ordering::SeqCst);
                response = Some(selected);
                match selected {
                    0 => {
                        // Use the actual approved acquisition text, also checked against
                        // its retained source below. A merely offered tool is insufficient.
                        let expected = self.script.expected_instruction.lock().unwrap();
                        let actual = request.request().messages.iter().rev().find_map(|message| match message {
                            Message::User(user) => Some(user.text_content()),
                            _ => None,
                        });
                        assert_eq!(actual.as_deref(), expected.as_deref(),
                            "the current B request must carry its approved task instruction");
                        let offered = request.request().tools.iter().filter(|tool|
                            tool.provenance.as_ref().is_some_and(|source|
                                source.kind == ToolSourceKind::Mcp && source.source_id.as_str() == "mail"))
                            .collect::<Vec<_>>();
                        assert_eq!(offered.len(), 1, "B must see the newly attached public tool");
                        let identity = offered[0].identity();
                        assert!(self.script.offered.lock().unwrap().replace(identity.clone()).is_none());
                        // Call the actual offered model-facing identity. The fixture
                        // never guesses a prefix or treats a raw operation as a name.
                        LlmEvent::ToolCallComplete {
                            id: PUBLIC_READ_CALL.into(), name: identity.name.as_str().to_owned(),
                            args: serde_json::json!({}), meta: None,
                        }
                    }
                    1 => {
                        let feedback = request.request().messages.iter().flat_map(|message| match message {
                            Message::ToolResults { results, .. } => results.as_slice(),
                            _ => &[],
                        }).filter(|result| result.tool_use_id == PUBLIC_READ_CALL).collect::<Vec<_>>();
                        assert_eq!(feedback.len(), 1, "the same task must receive one actual tool result");
                        let result = (*feedback[0]).clone();
                        assert!(!result.is_error && result.settlement_failures.is_empty(), "{result:?}");
                        let answer = format!("Public read completed: {}", result.text_content());
                        assert!(self.script.feedback.lock().unwrap().replace(result).is_none());
                        LlmEvent::TextDelta { delta: answer, meta }
                    }
                    _ => panic!("the public input must not replay model work"),
                }
            }
            LlmEvent::Done { outcome: LlmDoneOutcome::Success { .. } }
                if response == Some(0) => LlmEvent::Done {
                    outcome: LlmDoneOutcome::Success { stop_reason: StopReason::ToolUse },
                },
            other => other,
        })))
    }

    fn provider(&self) -> Provider { self.inner.provider() }
    async fn health_check(&self) -> Result<(), LlmError> { self.inner.health_check().await }
}

/// This replaces only the installed-package subprocess. Its answer must match
/// the actual canonical approved record and full configuration digest. No
/// readiness, actor, native authority or attachment receipt is supplied here.
struct ExactPackageReadback {
    evidence: PrivateSourceEvidence,
    config: meerkat_core::McpServerConfig,
    calls: AtomicUsize,
}
#[async_trait::async_trait]
impl ServiceInstallationReadback for ExactPackageReadback {
    async fn readback(
        &self,
        review: &ApprovalRecord,
    ) -> Result<meerkat_core::McpServerConfig, PrivateOriginalError> {
        let body = review
            .proposed_action
            .body
            .as_ref()
            .ok_or(PrivateOriginalError::Denied)?;
        if review.approval_id.to_string() != self.evidence.resource_id.as_str()
            || digest(&canonical_json(review).map_err(|_| PrivateOriginalError::Conflict)?)
                != self.evidence.sha256
            || review.status != ApprovalStatus::Approved
            || !review
                .decision
                .as_ref()
                .is_some_and(|d| d.decision == ApprovalDecision::Approve)
            || body["service_access"]["connection_revision"]
                != digest(&canonical_json(&self.config).unwrap())
        {
            return Err(PrivateOriginalError::Denied);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.config.clone())
    }
}

async fn approved_native(
    fixture: &PersistentFixture,
    endpoint: &Endpoint,
    public: bool,
) -> (
    PrivateOriginalRef,
    StoredRecord,
    ApprovedTaskLink,
    Arc<ExactPackageReadback>,
    String,
    String,
) {
    let a = fixture.submit().await;
    let a_input = match &a {
        Ok(PrivateOriginalSubmission::Admitted {
            session_id,
            input_id,
            ..
        }) => {
            assert_eq!(session_id, &fixture.session.to_string());
            input_id.clone()
        }
        _ => panic!("actual A submission did not return its native admission"),
    };
    fixture.finish(&a).await.unwrap();
    let dispatch = fixture.probe.as_ref().unwrap().captured();
    let run = dispatch.retained_work().unwrap().run_id().clone();
    tokio::time::timeout(
        WAIT,
        fixture.machine.wait_run_settled(&fixture.session, &run),
    )
    .await
    .unwrap();
    assert_eq!(
        fixture
            .machine
            .run_turn_terminal(&fixture.session, &run)
            .await,
        Some(TurnTerminalOutcome::Completed)
    );
    let snapshot = acquisition(fixture, &dispatch).await;
    let instruction = snapshot.request().request().request.clone();
    let mut config = endpoint.config(&fixture.scope.realm);
    if public {
        // Select the existing native NoConnector review branch explicitly.
        // The exact read ceiling remains in the reviewed MCP configuration.
        config.connector = None;
        config.access = Some(meerkat_core::McpServerAccess::allowing(["read".to_owned()]));
        config.tool_names.insert("read".into(), "attachment_public_read".into());
        assert!(meerkat::ConnectorMcpInstallation::from_config(&config).is_none());
    }
    let b = if public {
        // Raw MCP access and model-facing application invocation are separate.
        // Review only this mapped read, retaining the empty bootstrap policy.
        // The fixture checks the actual offered identity before calling it;
        // it does not request or use native catalog controls.
        approve_b_configuration_with_tool_policy(
            fixture, snapshot, [Id::new("read").unwrap()].into(), config.clone(),
            ServiceToolPolicySelection {
                tools: vec![crate::installed_host::tool_policy::ServiceToolInvocation {
                    name: config.tool_names.get("read").unwrap().clone(),
                    consequence: meerkat_core::CompiledToolConsequence::R0,
                }],
                catalog: None,
            },
        ).await
    } else {
        approve_b_configuration(
            fixture, snapshot, [Id::new("read").unwrap()].into(), Some(config.clone()),
        ).await
    };
    let stored = fixture
        .store
        .get(&fixture.source.key(&b).unwrap())
        .await
        .unwrap()
        .unwrap();
    let record = fixture.source.decode_record(&stored, &b).unwrap();
    assert_eq!(record.event.content_sha256, digest(instruction.as_bytes()),
        "the retained B source must bind the selected acquisition instruction");
    let task = record.approved_task.unwrap();
    let readback = Arc::new(ExactPackageReadback {
        evidence: record.event.original_authentication,
        config,
        calls: AtomicUsize::new(0),
    });
    fixture
        .source
        .bind_service_installation_readback(readback.clone())
        .unwrap();
    assert!(
        fixture
            .source
            .held_service_attachment(&b, &task)
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .source
            .attachment_parent(&task)
            .unwrap()
            .service_attachments
            .lock()
            .unwrap()
            .is_empty()
    );
    (b, stored, task, readback, a_input, instruction)
}

async fn assert_native_inputs(
    fixture: &PersistentFixture,
    runtime_store: &dyn RuntimeStore,
    expected: &[(&str, &InputAuthorityAssociation)],
) -> Vec<StoredInputState> {
    let rows = tokio::time::timeout(
        WAIT,
        runtime_store.load_input_states_strict(&LogicalRuntimeId::for_session(&fixture.session)),
    )
    .await
    .expect("canonical input history timed out")
    .expect("canonical input history must decode completely");
    let actual_ids = rows
        .iter()
        .map(|row| row.state.input_id.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    let expected_ids = expected
        .iter()
        .map(|(id, _)| (*id).to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        rows.len(),
        expected.len(),
        "no extra canonical native input rows"
    );
    assert_eq!(
        actual_ids, expected_ids,
        "exact native admission identities"
    );
    for (id, association) in expected {
        let row = rows
            .iter()
            .find(|row| row.state.input_id.to_string() == *id)
            .unwrap();
        assert!(
            row.state
                .authority_contributors
                .iter()
                .any(|authority| authority.input_id() == &row.state.input_id
                    && authority.association() == *association),
            "canonical input must retain the exact source association"
        );
    }
    rows
}

/// Persistent input history is authoritative after consumed inputs leave the
/// live ledger. Observe the exact B row and its run, not an input count or a
/// provider response alone. This only reads owners and never wakes the run.
async fn assert_public_input_completed(
    fixture: &PersistentFixture,
    runtime_store: &dyn RuntimeStore,
    original: &PrivateOriginalRef,
    input: &str,
    expected: &[(&str, &InputAuthorityAssociation)],
    expected_result: &str,
) {
    tokio::time::timeout(WAIT, async {
        loop {
            let rows = assert_native_inputs(fixture, runtime_store, expected).await;
            let row = rows
                .iter()
                .find(|row| row.state.input_id.to_string() == input)
                .unwrap();
            if row.seed.phase == InputLifecycleState::Consumed
                && row.seed.terminal_outcome == Some(InputTerminalOutcome::Consumed)
            {
                let run = row
                    .seed
                    .last_run_id
                    .as_ref()
                    .expect("B ran before consumption");
                if fixture.machine.run_turn_terminal(&fixture.session, run).await
                    == Some(TurnTerminalOutcome::Completed)
                    && fixture.machine.current_run(&fixture.session).await.as_ref() != Some(run)
                {
                    let native_input = InputId::from_uuid(input.parse().unwrap());
                    let terminal = fixture.machine.input_terminal_receipt(
                        &fixture.session, InteractionSelector::InputId(native_input.clone()),
                    ).await.unwrap().expect("B has an actual terminal receipt");
                    if let InputTerminalReceiptRead::Finalized(receipt) = terminal.report {
                        assert_eq!(receipt.input_id(), &native_input);
                        assert_eq!(receipt.owner_input_id(), &native_input);
                        assert_eq!(receipt.recipient_input_ids(), std::slice::from_ref(&native_input));
                        assert_eq!(receipt.run_id(), Some(run));
                        let CompletionOutcome::Completed(result) = receipt.outcome()
                            else { panic!("B must complete with its actual result") };
                        assert_eq!(result.session_id, fixture.session);
                        assert_eq!(result.text, format!("Public read completed: {expected_result}"));
                        assert_eq!(result.tool_calls, 1);
                        let projected = fixture.source.observe_service_input_receipt(original).await.unwrap();
                        let crate::private_originals::PrivateServiceInputObservation::Admitted {
                            session_id, input_id, receipt: Some(projected),
                        } = projected else { panic!("canonical B must expose its native receipt") };
                        assert_eq!(session_id, fixture.session.to_string());
                        assert_eq!(input_id, input);
                        assert!(matches!((projected.source, terminal.source),
                            (crate::private_originals::PrivateReceiptWitness::LiveRuntime,
                                meerkat_runtime::terminal_status::TerminalWitnessSource::LiveRuntime)
                            | (crate::private_originals::PrivateReceiptWitness::DurableStore,
                                meerkat_runtime::terminal_status::TerminalWitnessSource::DurableStore)));
                        let crate::private_originals::PrivateServiceInputReport::Finalized {
                            input_id, terminal, attempt_count, scope, run_id, owner_input_id,
                            recipient_input_ids, outcome,
                        } = projected.report else { panic!("the read must retain finalized state") };
                        assert_eq!(input_id, input);
                        assert_eq!(terminal, receipt.terminal().clone());
                        assert_eq!(attempt_count, receipt.attempt_count());
                        assert!(matches!(scope, crate::private_originals::PrivateReceiptScope::Run { run_id: scoped }
                            if scoped == run.to_string()));
                        assert_eq!(run_id, Some(run.to_string()));
                        assert_eq!(owner_input_id, input);
                        assert_eq!(recipient_input_ids, vec![input.to_owned()]);
                        assert_eq!(serde_json::to_value(outcome).unwrap(), serde_json::to_value(receipt.outcome()).unwrap());
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the exact public B input must complete and settle");
}

async fn actual_attachment_case(cancel: bool, public: bool) {
    let script = public.then(|| Arc::new(PublicReadScript::default()));
    let (fixture, runtime_store) = match &script {
        Some(script) => {
            let script = script.clone();
            PersistentFixture::for_live_attachment_with_model(move |inner| script.provider(inner)).await
        }
        None => PersistentFixture::for_live_attachment().await,
    };
    let endpoint = Endpoint::new();
    let outcome = AssertUnwindSafe(Box::pin(tokio::time::timeout(WAIT * 4, async {
        let (b, stored, task, readback, a_input, instruction) = approved_native(&fixture, &endpoint, public).await;
        let a_binding = fixture.binding().await.unwrap().unwrap();
        let a_only = [(a_input.as_str(), &a_binding)];
        let a_rows = assert_native_inputs(&fixture, runtime_store.as_ref(), &a_only).await;
        let a_dispatch = fixture.probe.as_ref().unwrap().captured();
        assert_eq!(
            a_rows[0].seed.last_run_id.as_ref(),
            Some(a_dispatch.retained_work().unwrap().run_id())
        );
        assert_eq!(a_rows[0].seed.phase, InputLifecycleState::Consumed);
        assert_eq!(
            a_rows[0].seed.terminal_outcome,
            Some(InputTerminalOutcome::Consumed)
        );
        let source = &fixture.source;
        assert!(matches!(source.observe_service_input_receipt(&b).await.unwrap(),
            crate::private_originals::PrivateServiceInputObservation::AdmissionUnresolved));
        let model_requests = fixture.model_requests();
        if let Some(script) = &script { script.arm(instruction); }
        let actor = fixture
            .service
            .live_session_actor_witness(&fixture.session)
            .await
            .unwrap();

        // A genuine held member turn boundary makes the native try-entry Busy.
        // It must leave no accepted keeper, child process or B binding behind.
        let lease = fixture
            .service
            .acquire_live_session_actor_turn_boundary_lease_exact(&actor)
            .await
            .unwrap()
            .unwrap();
        source
            .step_service_input_with_attachment(&fixture.store, &stored)
            .await
            .unwrap();
        assert!(source.held_service_attachment(&b, &task).unwrap().is_none());
        assert_eq!(endpoint.starts(), 0);
        assert_eq!(
            fixture.store.get(&stored.key).await.unwrap().unwrap(),
            stored
        );
        assert_native_inputs(&fixture, runtime_store.as_ref(), &a_only).await;
        drop(lease);
        let readbacks_before_entry = readback.calls.load(Ordering::SeqCst);

        // Enter the production preparation/call/observation path, still with
        // no keeper. Native starts the exact reviewed process and retains the
        // accepted attempt while its real tools/list answer is held.
        source
            .step_service_input_with_attachment(&fixture.store, &stored)
            .await
            .unwrap();
        endpoint.wait_for(&endpoint.listed).await;
        let held = source
            .held_service_attachment(&b, &task)
            .unwrap()
            .expect("actual accepted attempt retained");
        let receipt = held
            .receipt(|| panic!("entered native call cannot start twice"))
            .await
            .unwrap()
            .unwrap();
        assert!(receipt.outcome.staged && !receipt.outcome.persisted);
        assert_eq!(
            receipt.attempt.observe("read").await,
            McpAttachmentReadiness::Pending
        );
        assert_eq!(
            fixture
                .service
                .live_session_actor_witness(&fixture.session)
                .await
                .as_ref(),
            Some(&actor)
        );
        assert_eq!(
            fixture.store.get(&stored.key).await.unwrap().unwrap(),
            stored
        );
        assert_native_inputs(&fixture, runtime_store.as_ref(), &a_only).await;
        assert_eq!(fixture.model_requests(), model_requests);
        assert_eq!(endpoint.starts(), 1);
        assert_eq!(
            readback.calls.load(Ordering::SeqCst),
            readbacks_before_entry + 1
        );

        source
            .step_service_input_with_attachment(&fixture.store, &stored)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &held,
            &source.held_service_attachment(&b, &task).unwrap().unwrap()
        ));
        assert_eq!(
            fixture.store.get(&stored.key).await.unwrap().unwrap(),
            stored
        );
        assert_eq!(endpoint.starts(), 1);
        assert_eq!(
            readback.calls.load(Ordering::SeqCst),
            readbacks_before_entry + 1
        );
        if cancel {
            source
                .record_task_group_cancelled(&task.parent)
                .await
                .unwrap();
        }
        endpoint.release();
        if !cancel {
            assert!(matches!(
                receipt.attempt.wait("read", WAIT).await,
                McpAttachmentReadiness::Usable { .. }
            ));
            assert!(matches!(
                receipt.attempt.observe("not-reviewed-or-listed").await,
                McpAttachmentReadiness::ToolNotRouted { .. }
            ));
        }
        let current = fixture.store.get(&stored.key).await.unwrap().unwrap();
        source
            .step_service_input_with_attachment(&fixture.store, &current)
            .await
            .unwrap();
        let saved = fixture.store.get(&stored.key).await.unwrap().unwrap();
        let record = source.decode_record(&saved, &b).unwrap();
        if cancel {
            assert!(record.operation_cancelled);
            assert!(record.final_association.is_none() && record.service_admission.is_none());
            assert_native_inputs(&fixture, runtime_store.as_ref(), &a_only).await;
            assert_eq!(fixture.model_requests(), model_requests);
        } else {
            assert!(record.final_association.is_some() && record.service_admission.is_some());
            let admission = record.service_admission.as_ref().unwrap();
            assert_eq!(admission.session_id, fixture.session.to_string());
            assert_ne!(admission.input_id, a_input);
            let expected = [
                (a_input.as_str(), &a_binding),
                (
                    admission.input_id.as_str(),
                    record.final_association.as_ref().unwrap(),
                ),
            ];
            assert_native_inputs(&fixture, runtime_store.as_ref(), &expected).await;
            if public {
                assert_public_input_completed(
                    &fixture,
                    runtime_store.as_ref(),
                    &b,
                    &admission.input_id,
                    &expected,
                    &endpoint.result,
                )
                .await;
                assert_eq!(fixture.model_requests(), model_requests + 2);
                let calls = endpoint.calls();
                assert_eq!(calls.len(), 1, "one real tools/call reaches the attached process");
                assert_eq!(calls[0]["params"]["name"], "read");
                assert_eq!(calls[0]["params"]["arguments"], serde_json::json!({}));
                let script = script.as_ref().unwrap();
                assert_ne!(script.offered.lock().unwrap().as_ref().unwrap().name.as_str(), "read",
                    "the actual catalog supplies the exposed identity, while MCP receives raw read");
                assert_eq!(script.responses.load(Ordering::SeqCst), 2);
                let feedback = script.feedback.lock().unwrap();
                assert_eq!(feedback.as_ref().unwrap().text_content(), endpoint.result);
            }
        }
        assert!(source.held_service_attachment(&b, &task).unwrap().is_none());
        source
            .step_service_input_with_attachment(&fixture.store, &saved)
            .await
            .unwrap();
        let replay_saved = fixture.store.get(&stored.key).await.unwrap().unwrap();
        let replay = source.decode_record(&replay_saved, &b).unwrap();
        assert!(replay.service_admission == record.service_admission);
        assert!(replay.final_association == record.final_association);
        if let Some(admission) = &record.service_admission {
            assert_native_inputs(
                &fixture,
                runtime_store.as_ref(),
                &[
                    (a_input.as_str(), &a_binding),
                    (
                        admission.input_id.as_str(),
                        record.final_association.as_ref().unwrap(),
                    ),
                ],
            )
            .await;
        } else {
            assert_native_inputs(&fixture, runtime_store.as_ref(), &a_only).await;
        }
        if public {
            assert_eq!(
                fixture.model_requests(),
                if cancel { model_requests } else { model_requests + 2 },
                "recovery cannot replay consumed B or submit a cancelled B"
            );
            let script = script.as_ref().unwrap();
            assert_eq!(endpoint.calls().len(), if cancel { 0 } else { 1 });
            assert_eq!(script.responses.load(Ordering::SeqCst), if cancel { 0 } else { 2 });
            assert_eq!(script.offered.lock().unwrap().is_some(), !cancel);
            assert_eq!(script.feedback.lock().unwrap().is_some(), !cancel);
        }
        assert_eq!(
            endpoint.starts(),
            1,
            "no reattachment after readiness or canonical admission"
        );
        assert_eq!(
            readback.calls.load(Ordering::SeqCst),
            readbacks_before_entry + 1
        );
        if public && !cancel {
            // Revoking future operation use must not erase the exact completed
            // native fact. This read neither resubmits B nor resolves execution.
            source.cancel_original_operation(&b).await.unwrap();
            let admission = record.service_admission.as_ref().unwrap();
            assert_public_input_completed(&fixture, runtime_store.as_ref(), &b, &admission.input_id,
                &[(a_input.as_str(), &a_binding), (admission.input_id.as_str(), record.final_association.as_ref().unwrap())],
                &endpoint.result).await;
            assert_eq!(endpoint.calls().len(), 1);
            assert_eq!(fixture.model_requests(), model_requests + 2);
        }
    })))
    .catch_unwind()
    .await;
    // Failure-only observation of the SAME native runtime store. This reads
    // existing protected audit records before normal cleanup; it neither
    // authorizes an operation nor replaces the original failure or assertion.
    if public && !matches!(&outcome, Ok(Ok(()))) {
        let observed = tokio::time::timeout(WAIT,
            runtime_store.load_input_states_strict(&LogicalRuntimeId::for_session(&fixture.session))).await;
        match observed {
            Ok(Ok(rows)) => for row in rows {
                let Ok(encoded) = serde_json::to_value(&row) else { continue; };
                let Some(audit) = encoded.get("authorization_audit") else { continue; };
                let Ok(records) = serde_json::from_value::<Vec<
                    meerkat_authorization_contracts::audit::StoredAuthorizationAuditObservation
                >>(audit.clone()) else { continue; };
                for (index, record) in records.iter().enumerate() {
                    use meerkat_authorization_contracts::audit::{AuditObservation, AuditTarget};
                    let observation = &record.observation;
                    let (kind, target, reason, publication, observed_at) = match &observation.observation {
                        AuditObservation::Prepared { target, policy } =>
                            ("prepared", Some(target.as_ref()), None, Some(policy.publication_sequence), Some(policy.observed_at_ms)),
                        AuditObservation::Refused { target, reason } =>
                            ("refused", Some(target.as_ref()), Some(*reason), None, None),
                        AuditObservation::AuthorizationUnavailable { target } =>
                            ("authorization_unavailable", Some(target.as_ref()), None, None, None),
                        AuditObservation::Entry => ("entry", None, None, None, None),
                        AuditObservation::Outcome { .. } => ("outcome", None, None, None, None),
                        AuditObservation::ReviewAttemptStarted { .. } => ("review_attempt_started", None, None, None, None),
                        AuditObservation::MandatoryHookWithheld { .. } => ("mandatory_hook_withheld", None, None, None, None),
                    };
                    // Do not print prompts, tool arguments/digests, credentials,
                    // accounts, endpoints, grant lineages or output payloads.
                    let target = match target {
                        Some(AuditTarget::Model(model)) => serde_json::json!({
                            "kind": "model", "usage": model.usage,
                            "hosted_capability_count": model.hosted_capabilities.len(),
                        }),
                        Some(AuditTarget::Tool { call_id, tool_name, .. }) =>
                            serde_json::json!({"kind": "tool", "call_id": call_id, "tool_name": tool_name}),
                        Some(_) => serde_json::json!({"kind": "other"}),
                        None => serde_json::Value::Null,
                    };
                    eprintln!("{}", serde_json::json!({
                        "event": "attachment_control_native_authorization_audit",
                        "input_id": row.state.input_id, "index": index,
                        "operation_id": observation.operation_id, "run_id": observation.run_id,
                        "kind": kind, "target": target, "reason": reason,
                        "publication_sequence": publication, "observed_at_ms": observed_at,
                    }));
                }
            },
            _ => eprintln!("attachment control native audit observation unavailable"),
        }
    }
    // Release before shutdown on both success and panic. Native owns process
    // termination; this test does not kill a provider or detached OS process.
    endpoint.release();
    fixture.source.join_service_attachments().await;
    let cleanup = fixture.shutdown().await;
    assert!(cleanup.is_ok(), "{cleanup:?}");
    match outcome {
        Ok(Ok(())) => (),
        Ok(Err(_)) => panic!("actual persistent attachment control timed out"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_persistent_attachment_from_empty_keeper_gates_and_admits_b_once() {
    actual_attachment_case(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_pending_attachment_cannot_admit_b_after_parent_cancellation() {
    actual_attachment_case(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_public_attachment_calls_read_and_completes_exact_b_once_with_cancellation() {
    // Real native approval, Apply, readiness, invocation and exact completion;
    // the controlled local MCP/model do not establish live provider acceptance.
    for cancel in [false, true] {
        actual_attachment_case(cancel, true).await;
    }
}
