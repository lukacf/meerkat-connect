//! Canonical result storage and replay using the existing SQLite/WorkGraph
//! fixture. Native operation authorization deliberately denies in this fixture;
//! these controls do not qualify an installed helper or native delivery.
use super::*;
use crate::setup::{SetupHelperFailure, SetupHelperResultAccess};

async fn published_helper(
    f: &Fixture,
) -> (
    NativeWorkPreparation,
    SetupRequestEvidence,
    NativeHelperSource,
) {
    let preparation = prepare(f, "canonical helper input").await;
    let observed = graph_admit(f, &preparation).await;
    let (proposal, child, source) = helper_fixture(f, &preparation, &observed).await;
    f.bridge(&f.store)
        .publish_prepared_helper_work(
            &f.snapshot,
            &proposal,
            child.clone(),
            source.clone(),
            f.access(&f.context(f.now)),
            conditions(f, &source, &f.lease),
        )
        .await
        .unwrap();
    (preparation, child, source)
}
fn helper_context<'a>(
    child: &'a SetupRequestEvidence,
    authorization: &'a WorkAuthorizationContext,
    now_ms: u64,
) -> SetupUseContext<'a> {
    let c = child.constraints();
    SetupUseContext {
        tenant: &c.tenant,
        deployment: &c.deployment,
        realm: &child.association().candidate().ingress_namespace.realm,
        target: &child.association().candidate().target,
        policy_revision: &c.policy_revision,
        now_ms,
        authorization,
    }
}
fn access<'a>(
    source: &'a NativeHelperSource,
    input: &'a ContextReference,
    context: &'a SetupUseContext<'a>,
) -> SetupHelperResultAccess<'a> {
    SetupHelperResultAccess {
        helper: &source.association,
        source: &source.source,
        contributors: &source.contributors,
        effect: &source.effect,
        input_digest: &input.content_digest,
        context,
    }
}
fn report() -> SetupHelperFailure {
    SetupHelperFailure::Unavailable {
        detail: "This provider does not offer the requested export operation.".into(),
    }
}

#[tokio::test]
async fn canonical_helper_result_survives_lost_reply_and_binds_explanation_before_delivery() {
    let f = Fixture::new().await;
    let (preparation, child, source) = published_helper(&f).await;
    let operation = operation_id(f.snapshot.request()).unwrap();
    let authorization = native_fixture::current(child.association());
    let context = helper_context(&child, &authorization, f.now);
    let before = f.store.get(f.snapshot.key()).await.unwrap().unwrap();
    let initial_page = f.bridge(&f.store).continuation_recovery_page(None, 32).await.unwrap();
    assert!(initial_page.operations.is_empty());
    assert!(!initial_page.had_unavailable_records);
    assert!(before.data.body.get("helper_detail").is_none());
    let legacy = f.bridge(&f.store).recover(before.clone()).unwrap();
    assert_eq!(
        canonical_json(&legacy.record).unwrap(),
        canonical_json(&before.data.body).unwrap()
    );
    for detail in [String::new(), " ".into(), "x".repeat(4097)] {
        assert!(
            f.bridge(&f.store)
                .resolve_helper_failure(
                    &operation,
                    SetupHelperFailure::Failed { detail },
                    access(&source, preparation.input_reference(), &context),
                    &f.backend,
                    "invalid-detail"
                )
                .await
                .is_err()
        );
    }
    let first = f
        .bridge(&f.store)
        .resolve_helper_failure(
            &operation,
            report(),
            access(&source, preparation.input_reference(), &context),
            &f.backend,
            "result-fixture",
        )
        .await
        .unwrap();
    assert_eq!(first.phase, AcquisitionPhase::Unavailable);
    // No continuation owner has run: the result and handoff already coexist in
    // canonical storage and survive closing/reopening its real SQLite adapter.
    let reopened = SqliteStore::open(f.directory.path().join("store.sqlite")).unwrap();
    let bridge = f.bridge(&reopened);
    // Recovery selects the saved obligation without another helper call. The
    // cursor is exact scoped pagination, not a delivery or restart checkpoint.
    let page = bridge.continuation_recovery_page(None, 1).await.unwrap();
    assert_eq!(page.operations, vec![operation.clone()]);
    assert!(!page.had_unavailable_records);
    assert_eq!(page.next_after_id.as_deref(), Some(f.snapshot.key().id.as_str()));
    let next = bridge.continuation_recovery_page(page.next_after_id.as_deref(), 1).await.unwrap();
    assert!(next.operations.is_empty());
    assert!(next.next_after_id.is_none());
    for limit in [0, 65] {
        assert!(bridge.continuation_recovery_page(None, limit).await.is_err());
    }
    for scope in [SetupScope::new(id("foreign"), id("deployment")), SetupScope::new(id("tenant"), id("foreign"))] {
        let other = SetupStore::new_conditional(&reopened, scope).unwrap();
        let page = other.continuation_recovery_page(None, 32).await.unwrap();
        assert!(page.operations.is_empty());
        assert!(!page.had_unavailable_records);
    }
    let obligation = bridge
        .committed_continuation(&operation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        obligation.helper_detail(),
        Some("This provider does not offer the requested export operation.")
    );
    assert_eq!(
        obligation.continuation().audience,
        f.snapshot.request().host().continuation.audience
    );
    assert_eq!(obligation.original_work(), f.authority.original_work());
    let saved = reopened.get(f.snapshot.key()).await.unwrap().unwrap();
    let record = bridge.recover(saved.clone()).unwrap();
    assert!(record.record.continuation_receipt.is_none());
    let (expected_events, expected_effects) = handoffs(
        &record.record,
        vec![AcquisitionEffect::ContinuationRequested {
            operation_id: record.state().operation_id.clone(),
            continuation_id: record.state().continuation_id.clone(),
            terminal_revision: record.state().terminal_revision,
            outcome: record.state().lifecycle_phase,
        }],
    )
    .unwrap();
    assert_eq!(expected_events.len(), 1);
    assert_eq!(expected_effects.len(), 1);
    let effect = reopened
        .get_effect(&EffectKey {
            record: saved.key.clone(),
            id: expected_effects[0].id.clone(),
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(effect.intent, expected_effects[0]);
    let replay = bridge
        .resolve_helper_failure(
            &operation,
            report(),
            access(&source, preparation.input_reference(), &context),
            &f.backend,
            "replay-fixture",
        )
        .await
        .unwrap();
    assert_eq!(first.revision, replay.revision);
    assert_eq!(
        saved.content_digest,
        reopened
            .get(&saved.key)
            .await
            .unwrap()
            .unwrap()
            .content_digest
    );
    assert!(matches!(
        bridge
            .resolve_helper_failure(
                &operation,
                SetupHelperFailure::Failed {
                    detail: "Different result under the same acquisition.".into()
                },
                access(&source, preparation.input_reference(), &context),
                &f.backend,
                "conflicting-fixture"
            )
            .await,
        Err(SetupError::Store(StoreError::AdmissionConflict))
    ));
    // Changing the human explanation changes exact obligation content, while
    // the original task's delivery key remains the same and must conflict.
    let mut altered = obligation.clone();
    altered.helper_detail = Some("substituted content".into());
    assert_ne!(obligation.digest().unwrap(), altered.digest().unwrap());
    assert_eq!(
        obligation.delivery_identity().unwrap(),
        altered.delivery_identity().unwrap()
    );
}

#[tokio::test]
async fn helper_result_refuses_substituted_source_effect_parent_and_current_context() {
    let f = Fixture::new().await;
    let (preparation, child, source) = published_helper(&f).await;
    let operation = operation_id(f.snapshot.request()).unwrap();
    let authorization = native_fixture::current(child.association());
    let context = helper_context(&child, &authorization, f.now);
    for kind in [
        "helper",
        "effect",
        "acquisition",
        "source",
        "parent",
        "input",
    ] {
        let mut changed = source.clone();
        let mut input = preparation.input_reference().clone();
        match kind {
            "helper" => changed.association = f.authority.association().clone(),
            "effect" => changed.effect.id.push_str("-foreign"),
            "acquisition" => changed.effect.record.id.push_str("-foreign"),
            "source" => changed.source.key.id.push_str("-foreign"),
            "parent" => changed.contributors = vec![child.association().clone()],
            "input" => input.content_digest = ContentDigest::of_bytes(b"other input"),
            _ => unreachable!(),
        }
        assert!(
            f.bridge(&f.store)
                .resolve_helper_failure(
                    &operation,
                    report(),
                    access(&changed, &input, &context),
                    &f.backend,
                    "negative-fixture"
                )
                .await
                .is_err(),
            "{kind}"
        );
    }
    let wrong_context = helper_context(&child, &f.authorization, f.now);
    assert!(
        f.bridge(&f.store)
            .resolve_helper_failure(
                &operation,
                report(),
                access(&source, preparation.input_reference(), &wrong_context),
                &f.backend,
                "parent-context"
            )
            .await
            .is_err()
    );
    let mut stale = context;
    let old_revision = rev("replaced-policy");
    stale.policy_revision = &old_revision;
    assert!(
        f.bridge(&f.store)
            .resolve_helper_failure(
                &operation,
                report(),
                access(&source, preparation.input_reference(), &stale),
                &f.backend,
                "stale-policy"
            )
            .await
            .is_err()
    );
    assert!(
        f.bridge(&f.store)
            .committed_continuation(&operation)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn helper_report_shape_cannot_assert_ready_or_smuggle_authority() {
    for value in [
        serde_json::json!({"kind":"ready","detail":"done"}),
        serde_json::json!({"kind":"failed","detail":"No export","operation":"other"}),
        serde_json::json!({"kind":"failed","detail":"No export","authority":{}}),
    ] {
        assert!(serde_json::from_value::<SetupHelperFailure>(value).is_err());
    }
}
