//! Actual idle close/ordinary resume plus historical source custody only.
//! No recovery worker, in-progress startup or additional native input is tested.
use super::*;
use crate::private_originals::governed_submit::tests::first_input_tests::dedicated::{DedicatedFixture, DurableDedicated};
use meerkat_core::SessionServiceHistoryExt;
use meerkat_core::service::SessionHistoryQuery;
use meerkat_mobkit::identity_first::{AgentIdentity, TurnTicket, TurnOutcome, TurnOutput};
use meerkat_core::{
    authorization::{AuthorizationOperation, OperationAuthorizationFacts, PreparedAuthorizationBinding,
        SourceAuthorizationFacts, SourceAuthorizationTarget, SourceAuthorizationUse},
    exact_operation::OperationExecutionScope,
    lifecycle::InputId,
    memory::MemorySearchScope,
};

type PersistentDedicated = DedicatedFixture<meerkat::PersistentSessionService<meerkat::FactoryAgentBuilder>>;

pub(super) async fn finish(c: &PersistentDedicated, member: &str, input: &PrivateOriginalSubmission) {
    let PrivateOriginalSubmission::Admitted { turn_ticket: Some(ticket), .. } = input else { panic!("actual admission required") };
    assert!(matches!(c.f.source.bound_identity_runtime().unwrap().wait_for_turn(
        &AgentIdentity::parse(member).unwrap(), TurnTicket::parse(ticket).unwrap(), GUARD,
    ).await, TurnOutcome::Completed { output: TurnOutput::Text { .. } }));
}
pub(super) async fn ids(c: &PersistentDedicated, session: &meerkat_core::SessionId) -> Vec<InputId> {
    let rows = c.history.as_ref().unwrap().load_input_states_strict(
        &meerkat_runtime::LogicalRuntimeId::for_session(session)).await.unwrap();
    assert!(rows.len() <= 3, "bounded exact fixture input history");
    let mut ids: Vec<_> = rows.into_iter().map(|row| row.state.input_id).collect();
    ids.sort_by_key(|id| id.to_string());
    assert!(ids.windows(2).all(|pair| pair[0] != pair[1]));
    ids
}
async fn history(c: &PersistentDedicated) -> serde_json::Value {
    let rows = c.f.service.read_history(&c.lead_session, SessionHistoryQuery { offset: 0, limit: Some(100) }).await.unwrap();
    assert!(!rows.has_more);
    serde_json::to_value(rows.messages).unwrap()
}
pub(super) async fn close(c: &PersistentDedicated, body: Result<(), Box<dyn std::any::Any + Send>>) {
    let cleanup = AssertUnwindSafe(async { let result = c.close().await; assert!(result.is_ok(), "{result:?}"); }).catch_unwind().await;
    if let Err(panic) = body { std::panic::resume_unwind(panic); }
    if let Err(panic) = cleanup { std::panic::resume_unwind(panic); }
}
struct Saved {
    durable: DurableDedicated,
    association: meerkat_authorization_contracts::work_association::InputAuthorityAssociation,
    row: toolkit_store::StoredRecord,
    membership: SetupWorkflowWaiter,
    ids: Vec<InputId>,
    history: serde_json::Value,
}
async fn admit_then_close() -> Saved {
    let c = PersistentDedicated::persistent().await;
    let body = AssertUnwindSafe(Box::pin(async {
        c.f.source.prepare_workflow_parent_source(&c.parent.original).await.unwrap();
        let p = c.f.source.submit_authenticated_original(c.parent.clone()).await.unwrap();
        finish(&c, "planning_parent", &p).await;
        let probe = c.f.probe.as_ref().unwrap();
        assert_eq!(probe.captured().origin_session_id(), Some(&c.parent_session));
        // The shared provider captured P. Its joined turn permits the existing
        // probe to capture the next actual input, A, without changing authority.
        probe.arm_next_input();
        let a = c.f.submit().await;
        c.f.finish(&a).await.unwrap();
        let dispatch = probe.captured();
        assert_eq!(dispatch.origin_session_id(), Some(&c.f.session));
        let original = c.f.source.acquisition_original(&dispatch).await.unwrap();
        assert_eq!(original.source_record.key, c.f.source.key(c.f.original_reference()).unwrap());
        assert_eq!(original.original.association(), &c.f.binding().await.unwrap().unwrap());
        let planning = c.f.source.prepare_workflow_planning(&c.parent.original,
            c.lead.clone(), c.terms.clone(), c.lineage.clone()).await.unwrap();
        let (membership, snapshot) = join_waiter(&c.f, &planning, &original, &dispatch, &c.backend, &c.work, "restore-waiter").await;
        let admitted = native(planning.launch(&snapshot).await.unwrap());
        finish(&c, "planning_lead", &admitted).await;
        let PrivateOriginalSubmission::Admitted { input_id, .. } = admitted else { panic!("G admission") };
        let actual_id = InputId::from_uuid(input_id.parse().unwrap());
        let association = c.f.source.binding_evidence(&c.lead.original).await.unwrap().unwrap();
        let row = c.f.store.get(&c.f.source.key(&c.lead.original).unwrap()).await.unwrap().unwrap();
        let record = c.f.source.decode_record(&row, &c.lead.original).unwrap();
        assert!(matches!(&record.planning_source_evidence,
            Some(crate::private_originals::planning_source_evidence::PlanningSourceEvidence::Lead { parent }) if parent == &c.parent.original));
        let input = record.bound_service_input.as_ref().unwrap().decode().unwrap();
        tokio::time::timeout(GUARD, async {
            loop {
                let rows = c.history.as_ref().unwrap().load_input_states_strict(
                    &meerkat_runtime::LogicalRuntimeId::for_session(&c.lead_session)).await.unwrap();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].state.input_id, actual_id);
                meerkat_runtime::input_state::verify_exact_replay(&rows[0].state, &input).unwrap();
                if rows[0].state.persisted_input.is_none() { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("terminal G input body retires before restore");
        let ids = ids(&c, &c.lead_session).await;
        assert_eq!(ids, vec![actual_id]);
        Saved { durable: c.durable_state(), association, row, membership, ids, history: history(&c).await }
    })).catch_unwind().await;
    let cleanup = AssertUnwindSafe(async { let result = c.close().await; assert!(result.is_ok(), "{result:?}"); }).catch_unwind().await;
    // All first activation owners are dropped. Only paths, immutable selection
    // and evidence survive, as in the existing persistent first-input fixture.
    drop(c);
    match body {
        Err(panic) => std::panic::resume_unwind(panic),
        Ok(saved) => {
            if let Err(panic) = cleanup { std::panic::resume_unwind(panic); }
            saved
        }
    }
}

pub(super) fn assert_unattached_policy_closed(c: &PersistentDedicated,
    association: &meerkat_authorization_contracts::work_association::InputAuthorityAssociation)
{
    // An ungranted policy candidate exercises the actual singleton fallback
    // boundary. It neither enters native work nor creates another input.
    let binding = PreparedAuthorizationBinding::new(OperationAuthorizationFacts {
        operation_id: serde_json::from_str("\"00000000-0000-0000-0000-000000000004\"").unwrap(),
        execution_scope: OperationExecutionScope::Domain,
        run_id: None, context_revision: None,
        operation: AuthorizationOperation::Source(SourceAuthorizationFacts {
            usage: SourceAuthorizationUse::Read,
            target: SourceAuthorizationTarget::Memory(MemorySearchScope::for_session(c.lead_session.clone())),
        }),
    });
    assert!(matches!(c.f.source.workflow_call_for_policy(association, &binding),
        Err(PrivateOriginalError::Unavailable)), "unattached G must not select singleton policy");
    assert!(matches!(c.f.source.owner.check_workflow_member(
        &meerkat_runtime::LogicalRuntimeId::for_session(&c.lead_session), association, None),
        Err(meerkat_runtime::input_authority::NativeAdmissionError::Readiness(
            meerkat_core::authorization::ControllerReadinessFailure::PolicyUnavailable))),
        "the same incomplete controller keeps native input admission unavailable");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_resumed_g_restores_exact_native_custody_without_input() {
    let saved = admit_then_close().await;
    let c = PersistentDedicated::reopen(saved.durable).await;
    let body = AssertUnwindSafe(Box::pin(async {
        assert_eq!(c.f.model_requests(), 0, "idle resume cannot replay the model");
        assert!(c.member.session().is_err());
        assert!(!c.f.source.owner.has_admitted_source(&saved.association).unwrap());
        assert_eq!(ids(&c, &c.lead_session).await, saved.ids);
        c.member.restore_admitted_source().await.unwrap();
        assert!(c.member.session().is_err(), "historical source is not a completed workflow attachment");
        assert!(c.f.source.owner.has_admitted_source(&saved.association).unwrap());
        assert_eq!(c.f.source.owner.historical_task_custody_for_test(&saved.association), Some((true, true)));
        assert_unattached_policy_closed(&c, &saved.association);
        let p = c.f.source.binding_evidence(&c.parent.original).await.unwrap().unwrap();
        assert!(c.f.source.owner.has_admitted_source(&p).unwrap());
        assert!(crate::original_ingress::controller_only_basis(&p.candidate().authority_basis));
        assert_eq!(saved.association.candidate().contributing_work, vec![p.candidate().original_work.clone()]);
        // Canonical departure does not share the source publication. Historical
        // custody can replay after closure because neither policy gate opens.
        let closed = c.f.source.workflow_store().unwrap().depart_setup_workflow(&saved.membership).await.unwrap();
        assert_eq!(closed.active_waiters(), 0);
        c.member.restore_admitted_source().await.unwrap();
        assert_unattached_policy_closed(&c, &saved.association);
        assert_eq!(ids(&c, &c.lead_session).await, saved.ids);
        assert_eq!(history(&c).await, saved.history);
        assert_eq!(c.f.model_requests(), 0);
        assert_eq!(c.f.store.get(&saved.row.key).await.unwrap().unwrap(), saved.row);
    })).catch_unwind().await;
    close(&c, body).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_resumed_g_refuses_foreign_missing_changed_and_cancelled_evidence() {
    let saved = admit_then_close().await;
    let c = PersistentDedicated::reopen(saved.durable).await;
    let body = AssertUnwindSafe(Box::pin(async {
        let workflow = c.f.source.workflow_store().unwrap().workflow_ref(&c.terms).unwrap();
        let mut foreign = c.lead.original.clone();
        foreign.event_sha256 = "f".repeat(64);
        assert_eq!(c.f.source.restore_workflow_lead_source(&workflow, &foreign, &c.terms.lead).await,
            Err(PrivateOriginalError::Conflict));
        for changed in [false, true] {
            let row = c.f.store.get(&saved.row.key).await.unwrap().unwrap();
            let mut data = saved.row.data.clone();
            if changed { data.body["bound_service_input"]["content"] = serde_json::json!("changed G request"); }
            else { data.body.as_object_mut().unwrap().remove("bound_service_input"); }
            c.f.store.compare_and_swap(toolkit_store::Transition { key: row.key, expected_revision: row.revision,
                expected_digest: Some(row.content_digest), claim: None, data, events: vec![], effects: vec![],
            }).await.unwrap();
            assert_eq!(c.member.restore_admitted_source().await,
                Err(if changed { PrivateOriginalError::Conflict } else { PrivateOriginalError::Unavailable }));
            assert!(c.member.session().is_err());
            assert!(!c.f.source.owner.has_admitted_source(&saved.association).unwrap());
            let p = c.f.source.binding_evidence(&c.parent.original).await.unwrap().unwrap();
            assert!(!c.f.source.owner.has_admitted_source(&p).unwrap(),
                "invalid G evidence must refuse before promoting P");
        }
        let row = c.f.store.get(&saved.row.key).await.unwrap().unwrap();
        c.f.store.compare_and_swap(toolkit_store::Transition { key: row.key, expected_revision: row.revision,
            expected_digest: Some(row.content_digest), claim: None, data: saved.row.data.clone(), events: vec![], effects: vec![],
        }).await.unwrap();
        c.f.source.record_operation_cancelled(&c.lead.original).await.unwrap();
        assert_eq!(c.member.restore_admitted_source().await, Err(PrivateOriginalError::Denied));
        assert!(c.member.session().is_err());
        assert!(c.f.source.owner.historical_task_custody_for_test(&saved.association).is_none());
        assert_eq!(ids(&c, &c.lead_session).await, saved.ids);
        assert_eq!(history(&c).await, saved.history);
        assert_eq!(c.f.model_requests(), 0);
    })).catch_unwind().await;
    close(&c, body).await;
}
