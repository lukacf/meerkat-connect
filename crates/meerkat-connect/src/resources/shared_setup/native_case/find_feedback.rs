//! This controlled model may propose one fresh local Find after exact native
//! authorization feedback. It is not a product retry or a generic classifier.
use super::*;
use meerkat_authorization::grant_policy::{ControllerAdmissionAllowance, OperationPolicyOwner};
use meerkat_authorization::policy::{LocalPolicyAllowance, LocalPolicyPurpose};
use meerkat_authorization_contracts::work_association::InputAuthorityAssociation;
use meerkat_core::authorization::{
    AuthorizationOperation, OperationAuthorizationError, PreparedAuthorizationBinding,
};
use meerkat_core::{ToolError, ToolResult};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum RefusalMode {
    #[default]
    None,
    First,
    Both,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum FindChoice {
    Emit(&'static str),
    Accepted,
    Exhausted,
}

pub(super) fn request_arguments(tag: &str) -> Value {
    json!({"request":format!("sdk-child-{tag}: inspect and prepare the selected inert software; report activation honestly")})
}
pub(super) fn canonical_unavailable(result: &ToolResult) -> bool {
    result.is_error
        && result.settlement_failures.is_empty()
        && *result
            == meerkat_core::ops::terminal_tool_outcome_for_error(
                result.tool_use_id.clone(),
                ToolError::OperationAuthorizationUnavailable,
            )
            .result
}
impl Script {
    pub(super) fn observe_result(&self, result: &ToolResult) -> bool {
        let mut seen = self.seen_results.lock().unwrap();
        if let Some(prior) = seen.get(&result.tool_use_id) {
            assert_eq!(
                prior, result,
                "a historical result identity must keep its original content"
            );
            false
        } else {
            seen.insert(result.tool_use_id.clone(), result.clone());
            true
        }
    }
    pub(super) fn find_choice(&self, prefix: &str, args: &Value) -> FindChoice {
        let calls = self.calls.lock().unwrap();
        let find = calls
            .iter()
            .filter(|(key, name, _)| {
                key.starts_with(&format!("{prefix}-")) && name == toolkit_mobkit::FIND_AND_INSTALL
            })
            .collect::<Vec<_>>();
        assert!(
            find.len() <= 2,
            "one fresh Find proposal is the complete bound"
        );
        for (index, (key, _, actual_args)) in find.iter().enumerate() {
            assert_eq!(
                key,
                &format!(
                    "{prefix}-{}",
                    if index == 0 { "find" } else { "find-fresh" }
                )
            );
            assert_eq!(
                actual_args, args,
                "fresh proposal preserves the canonical user request"
            );
        }
        let Some((key, _, _)) = find.last() else {
            return FindChoice::Emit("find");
        };
        let seen = self.seen_results.lock().unwrap();
        let result = seen
            .get(key)
            .expect("another model choice requires the actual previous result");
        if !result.is_error {
            return FindChoice::Accepted;
        }
        assert!(
            canonical_unavailable(result),
            "only exact local pre-entry feedback permits a fresh proposal"
        );
        if find.len() == 1 {
            FindChoice::Emit("find-fresh")
        } else {
            FindChoice::Exhausted
        }
    }
}

// Opt-in only for the two focused controls. All genuine allowance checks run
// first; selected calls then receive an actual typed native preparation error.
// Normal SDK acceptance installs no wrapper and keeps the configured owner.
pub(super) struct FindRefusalOwner {
    pub(super) inner: Arc<dyn OperationPolicyOwner>,
    pub(super) script: Arc<Script>,
}
impl OperationPolicyOwner for FindRefusalOwner {
    fn authorize_tool_application(
        &self,
        control: &meerkat_core::ToolApplicationControlRequest,
        binding: &PreparedAuthorizationBinding,
        now_ms: u64,
    ) -> Result<LocalPolicyAllowance, OperationAuthorizationError> {
        self.inner
            .authorize_tool_application(control, binding, now_ms)
    }
    fn authorize_context_control(
        &self,
        control: &meerkat_core::service::SystemContextControlRequest,
        binding: &PreparedAuthorizationBinding,
        now_ms: u64,
    ) -> Result<LocalPolicyAllowance, OperationAuthorizationError> {
        self.inner
            .authorize_context_control(control, binding, now_ms)
    }
    fn authorize_mcp_attachment(
        &self,
        control: &meerkat_core::mcp_attachment_control::McpAttachmentControlRequest,
        binding: &PreparedAuthorizationBinding,
        now_ms: u64,
    ) -> Result<LocalPolicyAllowance, OperationAuthorizationError> {
        self.inner
            .authorize_mcp_attachment(control, binding, now_ms)
    }
    fn authorize_controller_admission(
        &self,
        association: &InputAuthorityAssociation,
        facts: &meerkat_core::ControllerModelFacts,
        now_ms: u64,
    ) -> Result<ControllerAdmissionAllowance, OperationAuthorizationError> {
        self.inner
            .authorize_controller_admission(association, facts, now_ms)
    }
    fn authorize_operation(
        &self,
        association: &InputAuthorityAssociation,
        binding: &PreparedAuthorizationBinding,
        purpose: LocalPolicyPurpose,
        now_ms: u64,
    ) -> Result<LocalPolicyAllowance, OperationAuthorizationError> {
        let result = self
            .inner
            .authorize_operation(association, binding, purpose, now_ms)?;
        if let AuthorizationOperation::Tool(tool) = &binding.facts().operation {
            let call_id = tool.call_id.as_ref();
            let selected = tool.name.as_str() == toolkit_mobkit::FIND_AND_INSTALL
                && (call_id == "a-original-find"
                    || (self.script.find_refusals == RefusalMode::Both
                        && call_id == "a-original-find-fresh"));
            if selected {
                let calls = self.script.calls.lock().unwrap();
                assert_eq!(
                    calls
                        .iter()
                        .filter(|(key, name, args)| key == call_id
                            && name == toolkit_mobkit::FIND_AND_INSTALL
                            && args == &request_arguments("a"))
                        .count(),
                    1
                );
                let operation = binding.facts().operation_id.to_string();
                let mut injected = self.script.injected_find.lock().unwrap();
                if let Some(prior) = injected.insert(call_id.to_owned(), operation.clone()) {
                    assert_eq!(prior, operation);
                }
                eprintln!(
                    "{}",
                    json!({"event":"sdk_find_control_native_refusal", "call_id":call_id,
                    "operation_id":operation, "session":association.candidate().target.context.as_str()})
                );
                return Err(OperationAuthorizationError::Unavailable);
            }
        }
        Ok(result)
    }
    fn review_action_account(
        &self,
        association: &InputAuthorityAssociation,
        binding: &PreparedAuthorizationBinding,
        now_ms: u64,
    ) -> Result<Option<String>, OperationAuthorizationError> {
        self.inner
            .review_action_account(association, binding, now_ms)
    }
}

impl Case {
    async fn find_audits(
        &self,
        tag: &str,
        wait_terminal: bool,
    ) -> Vec<meerkat_authorization_contracts::audit::StoredAuthorizationAuditObservation> {
        let session = self.audit_sessions.get(&format!("original-{tag}")).unwrap();
        let runtime = meerkat_runtime::identifiers::LogicalRuntimeId::for_session(session);
        let store = self.audit_store.as_ref().unwrap();
        tokio::time::timeout(BOUND, async {
            loop {
                let rows = store.load_input_states_strict(&runtime).await.unwrap();
                assert!(rows.len() <= 16);
                if wait_terminal && !rows.iter().any(|row| row.seed.terminal_outcome.is_some()) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                let mut audit = Vec::new();
                for row in rows {
                    let encoded = serde_json::to_value(&row).unwrap();
                    let records: Vec<
                        meerkat_authorization_contracts::audit::StoredAuthorizationAuditObservation,
                    > = serde_json::from_value(
                        encoded
                            .get("authorization_audit")
                            .cloned()
                            .unwrap_or_else(|| json!([])),
                    )
                    .unwrap();
                    assert!(records.len() <= 512);
                    eprintln!(
                        "{}",
                        json!({"event":"sdk_find_native_audit", "member":tag,
                        "session":session.to_string(), "input_id":row.state.input_id.to_string(),
                        "terminal":row.seed.terminal_outcome.is_some(), "records":records})
                    );
                    audit.extend(records);
                    assert!(audit.len() <= 512, "bounded complete session audit");
                }
                break audit;
            }
        })
        .await
        .expect("bounded actual native audit read")
    }

    pub(super) async fn assert_find_feedback(&self, tags: &[&str], accepted: bool) {
        use meerkat_authorization_contracts::audit::{AuditObservation, AuditTarget};
        for tag in tags {
            let prefix = format!("{tag}-original");
            let audit = self.find_audits(tag, self.script.find_only).await;
            let calls = self
                .script
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, name, _)| {
                    key.starts_with(&format!("{prefix}-"))
                        && name == toolkit_mobkit::FIND_AND_INSTALL
                })
                .cloned()
                .collect::<Vec<_>>();
            assert!(!calls.is_empty() && calls.len() <= 2);
            let mut operation_ids = BTreeSet::new();
            let seen = self.script.seen_results.lock().unwrap();
            let mut successful = 0;
            for (call_id, _, args) in calls {
                assert_eq!(args, request_arguments(tag));
                let matches_call = |target: &AuditTarget| {
                    matches!(target, AuditTarget::Tool { call_id: actual, tool_name, .. }
                    if actual.as_str() == call_id && tool_name.as_str() == toolkit_mobkit::FIND_AND_INSTALL)
                };
                let ids = audit
                    .iter()
                    .filter_map(|record| {
                        let o = &record.observation;
                        let target = match &o.observation {
                            AuditObservation::Prepared { target, .. }
                            | AuditObservation::AuthorizationUnavailable { target }
                            | AuditObservation::Refused { target, .. } => Some(target.as_ref()),
                            _ => None,
                        };
                        target
                            .filter(|target| matches_call(target))
                            .map(|_| o.operation_id.to_string())
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(ids.len(), 1, "each emitted Find has one actual operation");
                let operation_id = ids.into_iter().next().unwrap();
                assert!(
                    operation_ids.insert(operation_id.clone()),
                    "fresh Find requires a distinct native operation"
                );
                let history = audit
                    .iter()
                    .filter(|record| record.observation.operation_id.to_string() == operation_id)
                    .collect::<Vec<_>>();
                let result = seen
                    .get(&call_id)
                    .expect("actual model-visible result retained");
                if result.is_error {
                    assert!(canonical_unavailable(result));
                    if self.script.find_refusals != RefusalMode::None {
                        assert_eq!(
                            self.script.injected_find.lock().unwrap().get(&call_id),
                            Some(&operation_id),
                            "actual configured refusal and retained audit join"
                        );
                    }
                    assert!(history.iter().any(|r| matches!(
                        r.observation.observation,
                        AuditObservation::AuthorizationUnavailable { .. }
                    )));
                    assert!(
                        !history.iter().any(|r| matches!(
                            r.observation.observation,
                            AuditObservation::Prepared { .. } | AuditObservation::Entry { .. }
                        )),
                        "the fresh-proposal fixture requires complete actual pre-entry evidence"
                    );
                } else {
                    successful += 1;
                    assert!(history.iter().any(|r| matches!(
                        r.observation.observation,
                        AuditObservation::Prepared { .. }
                    )));
                    assert!(history.iter().any(|r| matches!(
                        r.observation.observation,
                        AuditObservation::Entry {
                            boundary: Some(meerkat_core::OperationEntryBoundary::ToolEffect)
                        }
                    )));
                }
                eprintln!(
                    "{}",
                    json!({"event":"sdk_find_native_proof", "member":prefix,
                    "call_id":call_id, "operation_id":operation_id, "successful":!result.is_error,
                    "audit_records":history.len()})
                );
            }
            assert_eq!(successful, usize::from(accepted));
        }
        self.assert_acquisition_count(if accepted { tags.len() } else { 0 });
    }

    fn assert_acquisition_count(&self, expected: usize) {
        use std::os::unix::fs::MetadataExt;
        let realm = meerkat_core::mob_realm_id(MOB).unwrap().to_string();
        let path = self
            .directory
            .path()
            .join("shared/data/toolkit-native")
            .join(digest(realm.as_bytes()))
            .join("originals.sqlite3")
            .canonicalize()
            .unwrap();
        let held = fs::File::open(&path).unwrap();
        let before = held.metadata().unwrap();
        let db = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        db.busy_timeout(Duration::from_secs(1)).unwrap();
        let mut query = db.prepare("SELECT owner,id,data FROM toolkit_records WHERE realm=?1 ORDER BY owner,id LIMIT 65").unwrap();
        let rows = query
            .query_map([&realm], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(rows.len() < 65);
        let acquisitions = rows
            .into_iter()
            .filter(|(_, _, raw)| {
                let data: toolkit_store::RecordData = serde_json::from_str(raw).unwrap();
                data.schema == "meerkat_toolkit.acquisition"
            })
            .collect::<Vec<_>>();
        assert_eq!(
            acquisitions.len(),
            expected,
            "failed pre-entry proposals create no extra acquisition"
        );
        for (owner, record, _) in acquisitions {
            let mut query = db.prepare("SELECT data FROM toolkit_effects WHERE realm=?1 AND owner=?2 AND record_id=?3 ORDER BY id LIMIT 17").unwrap();
            let rows = query
                .query_map(rusqlite::params![realm, owner, record], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert!(rows.len() < 17);
            let work = rows
                .into_iter()
                .map(|raw| serde_json::from_str::<toolkit_store::StoredEffect>(&raw).unwrap())
                .filter(|effect| effect.intent.kind == "work_admission_requested")
                .collect::<Vec<_>>();
            assert_eq!(work.len(), 1);
            assert_eq!(work[0].status, toolkit_store::EffectStatus::Succeeded);
            assert!(matches!(
                work[0].outcome,
                Some(toolkit_store::EffectOutcome::Succeeded { .. })
            ));
        }
        let after = fs::metadata(&path).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        eprintln!(
            "{}",
            json!({"event":"sdk_find_acquisition_proof","acquisitions":expected,
            "succeeded_work_admission_effects":expected,"read_only_same_inode":true})
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(results: Vec<ToolResult>) -> LlmRequest {
        let mut request = LlmRequest::new(
            MODEL,
            vec![
                Message::User(meerkat_core::UserMessage::text(
                    "sdk-child-a: bounded local Find control",
                )),
                Message::tool_results(results),
            ],
        );
        request.tools.push(Arc::new(ToolDef::new(
            toolkit_mobkit::FIND_AND_INSTALL,
            "Existing local Find registration in the controlled model fixture",
            json!({"type":"object"}),
        )));
        request
    }
    fn unavailable(call: &str) -> ToolResult {
        meerkat_core::ops::terminal_tool_outcome_for_error(
            call,
            ToolError::OperationAuthorizationUnavailable,
        )
        .result
    }
    fn selected(events: &[LlmEvent]) -> Vec<String> {
        events
            .iter()
            .filter_map(|event| match event {
                LlmEvent::ToolCallComplete { id, .. } => Some(id.clone()),
                _ => None,
            })
            .collect()
    }
    fn new_script() -> Script {
        let script = Script::default();
        script
            .find_deadline
            .set(tokio::time::Instant::now() + BOUND)
            .unwrap();
        script
    }

    #[test]
    fn historical_find_feedback_does_not_emit_another_proposal() {
        let script = new_script();
        assert_eq!(
            selected(&script.response(&request(vec![]))),
            vec!["a-original-find"]
        );
        let refused = unavailable("a-original-find");
        assert_eq!(
            selected(&script.response(&request(vec![refused.clone(), refused.clone()]))),
            vec!["a-original-find-fresh"]
        );
        let accepted = ToolResult::new("a-original-find-fresh".into(), "{}".into(), false);
        for _ in 0..3 {
            assert!(
                selected(&script.response(&request(vec![refused.clone(), accepted.clone()])))
                    .is_empty()
            );
        }
        assert_eq!(script.calls.lock().unwrap().len(), 2);
        assert_eq!(script.seen_results.lock().unwrap().len(), 2);
        let calls = script.calls.lock().unwrap();
        assert_eq!(calls[0].2, calls[1].2);
    }

    #[test]
    fn nonmatching_and_settled_errors_never_propose_a_fresh_find() {
        let mut settled = unavailable("a-original-find");
        settled
            .settlement_failures
            .push(meerkat_core::ops::ToolDispatchSettlementFailure {
            admission_source: meerkat_core::ops::ToolDispatchAdmissionSource::AuthorizationAudit,
            effect_kind: meerkat_core::LiveBridgeEffectKind::ToolDispatch,
            physical_outcome: meerkat_core::LiveBridgeEffectOutcome::Committed,
            failure_kind:
                meerkat_core::ops::ToolDispatchTerminalErrorKind::OperationObservationUnavailable,
        });
        let uncertain = meerkat_core::ops::terminal_tool_outcome_for_error(
            "a-original-find",
            ToolError::OutcomeUncertain {
                name: toolkit_mobkit::FIND_AND_INSTALL.into(),
                reason: "controlled".into(),
            },
        )
        .result;
        for refused in [
            ToolResult::new(
                "a-original-find".into(),
                json!({"error":"tool_unavailable"}).to_string(),
                true,
            ),
            ToolResult::new(
                "a-original-find".into(),
                json!({"error":"operation_authorization_unavailable","extra":true}).to_string(),
                true,
            ),
            uncertain,
            settled,
        ] {
            let script = new_script();
            script.response(&request(vec![]));
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                script.response(&request(vec![refused]))
            }));
            assert!(outcome.is_err());
            assert_eq!(script.calls.lock().unwrap().len(), 1);
        }
        let script = new_script();
        script.calls.lock().unwrap().push((
            "a-original-other".into(),
            "arbitrary_mcp".into(),
            json!({}),
        ));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            script.response(&request(vec![unavailable("a-original-other")]))
        }));
        assert!(outcome.is_err());
        assert_eq!(script.calls.lock().unwrap().len(), 1);
        let script = new_script();
        script.calls.lock().unwrap().push((
            "a-helper-find".into(),
            toolkit_mobkit::FIND_AND_INSTALL.into(),
            request_arguments("a"),
        ));
        let mut helper_request = request(vec![unavailable("a-helper-find")]);
        helper_request.tools.push(Arc::new(ToolDef::new(
            meerkat_toolkit::setup::SETUP_REPORT,
            "Existing helper identity discriminator",
            json!({"type":"object"}),
        )));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            script.response(&helper_request)
        }));
        assert!(outcome.is_err());
        assert_eq!(script.calls.lock().unwrap().len(), 1);
    }

    fn event() -> (PrivateAuthenticatedEvent, String) {
        let content = request_arguments("a")["request"]
            .as_str()
            .unwrap()
            .to_owned();
        (
            PrivateAuthenticatedEvent {
                route: id("original-a"),
                original: evidence("sdk-child-a"),
                occurrence: evidence("sdk-occurrence-a"),
                original_authentication: PrivateSourceEvidence {
                    resource_id: evidence("sdk-auth-a"),
                    revision: evidence("1"),
                    sha256: digest(b"authenticated SDK occurrence a"),
                },
                root_event: PrivateSourceEvidence {
                    resource_id: evidence("sdk-root-a"),
                    revision: evidence("1"),
                    sha256: digest(content.as_bytes()),
                },
                contributors: vec![],
                content_sha256: digest(content.as_bytes()),
            },
            content,
        )
    }
    fn native_control(mode: RefusalMode) {
        let (pipes, parent) = SdkParent::pair();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let mut case = Case::new(parent.enter());
            case.script = Arc::new(Script { find_only: true, find_refusals: mode, ..Script::default() });
            let result = std::panic::AssertUnwindSafe(async {
                case.construct(pipes).await;
                case.script.find_deadline.set(tokio::time::Instant::now() + BOUND).unwrap();
                let launch = case.launch.as_ref().unwrap().clone();
                launch.create_parent().await;
                let (event, content) = event();
                tokio::time::timeout(BOUND, launch.launch(
                    meerkat_workgraph::WorkOwnerKey::agent("sdk-original-a").unwrap(), event, content))
                    .await.unwrap().unwrap().unwrap();
                // Wait for the real native input's terminal record, not a flag
                // set by the scripted model before its response is committed.
                case.assert_find_feedback(&["a"], mode == RefusalMode::First).await;
                let calls = case.script.calls.lock().unwrap();
                assert_eq!(calls.iter().filter(|(_,name,_)| name == toolkit_mobkit::FIND_AND_INSTALL).count(),2);
                assert!(calls.iter().all(|(_,name,_)| name == toolkit_mobkit::FIND_AND_INSTALL));
                let injected = case.script.injected_find.lock().unwrap();
                assert_eq!(injected.len(), if mode == RefusalMode::First { 1 } else { 2 },
                    "the exact configured owner must have produced the intended actual pre-entry refusal");
                assert!(!case.directory.path().join("physical/WORKER-ENTERED.json").exists());
            }).catch_unwind().await;
            let cleanup = case.cleanup().await;
            assert!(cleanup.is_empty(), "all actual SDK/native/physical owners settle: {cleanup:?}");
            if let Err(payload) = result { std::panic::resume_unwind(payload); }
        });
    }
    #[test]
    fn actual_first_find_refusal_then_fresh_find_creates_one_acquisition() {
        native_control(RefusalMode::First);
    }
    #[test]
    fn actual_persistent_find_refusal_stops_after_two_proposals() {
        native_control(RefusalMode::Both);
    }
}
