//! Real helper binder/native delivery with mechanical source-login custody.
//! No Human, Console principal, native approval, input or receipt is fabricated.
//! The existing local/operator fixture provides all authority; this extra login
//! handle exercises the production contributor collector and native entry fence.
use super::*;
use crate::private_host::{ConsoleLoginHandle, ConsoleLoginSelection, ConsoleLogins};
use meerkat_authorization_contracts::work_association::InputAuthorityAssociation;
use std::time::{SystemTime, UNIX_EPOCH};
use toolkit_store::ToolkitStore;

type Fixture = FirstFixture<meerkat::PersistentSessionService<FactoryAgentBuilder>>;

fn enrolled_login() -> (
    tokio::sync::watch::Sender<bool>,
    ConsoleLogins,
    ConsoleLoginHandle,
) {
    let (connection, owner) = ConsoleLogins::fixture_owner();
    let login = owner
        .fixture_enroll(
            1,
            ConsoleLoginSelection {
                issuer: "https://helper-entry.fixture.invalid".into(),
                subject: "mechanical-lifetime".into(),
                login_scope_id: "one-retained-login".into(),
                expires_at_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64
                    + 60_000,
            },
        )
        .unwrap();
    (connection, owner, login)
}

/// Attach only a lifetime to the actual retained A while physical scripted
/// output is paused. Its already admitted native authority remains unchanged.
fn retain_actual_a_login(
    fixture: &Fixture,
    binding: &InputAuthorityAssociation,
    login: &ConsoleLoginHandle,
) {
    let held = {
        let retained = fixture.source.retained.lock().unwrap();
        let exact: Vec<_> = retained
            .iter()
            .filter(|held| held.reference == fixture.submission.original)
            .cloned()
            .collect();
        assert_eq!(exact.len(), 1, "one exact retained original owner");
        exact[0].clone()
    };
    assert_eq!(held.original.association(), binding);
    assert!(held.console_login.set(login.clone()).is_ok());
    assert!(held.console_login.get().unwrap().same_owner(login));
}

async fn issued_helper(
    fixture: &Fixture,
    helper_session: &SessionId,
    original: &InputAuthorityAssociation,
) -> Arc<setup_helpers::HeldSetupHelper> {
    let held = {
        let helpers = fixture.source.helper_sources.lock().unwrap();
        assert_eq!(
            helpers.len(),
            1,
            "one actual issued and published helper source"
        );
        helpers[0].clone()
    };
    let binding = held.original().association();
    assert_eq!(
        binding.candidate().target.context.as_str(),
        helper_session.to_string()
    );
    assert!(crate::original_ingress::controller_only_basis(
        &binding.candidate().authority_basis
    ));
    assert_eq!(
        binding.candidate().authority_basis.grant_lineages().count(),
        0
    );
    let lineage = &binding.candidate().controller_grant_lineage;
    assert_eq!(
        lineage.len(),
        2,
        "actual independent controller parent and issued child"
    );
    assert_ne!(lineage, &original.candidate().controller_grant_lineage);
    fixture
        .source
        .owner
        .grants()
        .resolve_controller_lineage(
            lineage,
            &binding.candidate().logical_executor,
            binding.candidate().represented_subject.as_ref(),
        )
        .unwrap()
        .check_current()
        .unwrap();
    let facts = fixture
        .source
        .helper_policy_source(binding)
        .unwrap()
        .unwrap();
    assert_eq!(facts.contributors, vec![original.clone()]);
    assert_eq!(
        fixture
            .store
            .get(&held.source_record().key)
            .await
            .unwrap()
            .unwrap(),
        *held.source_record().as_ref()
    );
    held
}

fn tool_reply(script: &acquisition_denial::Script) -> serde_json::Value {
    let (feedback, planned, entered) = script.observations();
    assert_eq!(feedback.len(), 1, "one actual in-turn result: {feedback:?}");
    assert!(!feedback[0].is_error, "{feedback:?}");
    assert!(planned > 0, "real native tool resolution");
    assert_eq!(entered, 1, "one actual enrolled find_and_install call");
    serde_json::from_str(&feedback[0].text_content()).unwrap()
}

async fn exercise(mode: DeliveryMode) {
    let (_connection, logins, login) = enrolled_login();
    let script = acquisition_denial::Script::paused_for_helper_entry();
    let fault = Arc::new(DeliveryFault::new(mode));
    let (fixture, history) = Fixture::for_helper_entry(script.clone(), fault.clone()).await;
    let deadline = tokio::time::Instant::now() + WAIT;
    let checked = std::panic::AssertUnwindSafe(tokio::time::timeout_at(
        deadline,
        Box::pin(async {
            let helper =
                AgentIdentity::parse(crate::installed_host::controller_first_input_fixture::HELPER)
                    .unwrap();
            let helper_session = fault.helper_session.get().unwrap().clone();
            assert_ne!(helper_session, fixture.session);
            let helper_before = fixture.runtime.completion_cursor(&helper).await;
            assert!(
                acquisition_approved::native_history(history.as_ref(), &helper_session)
                    .await
                    .is_empty()
            );
            // Public external work stays refused even when the same private
            // helper later receives an actually authorized governed input.
            use crate::installed_host::controller_first_input_fixture as installed;
            let handle = fixture.native.mob_handle();
            let helper_member = MemberIdentity::from(installed::HELPER);
            let original_member = MemberIdentity::from(MEMBER);
            let definition = handle.definition();
            assert!(definition.profiles.get(&ProfileName::from("worker"))
                .unwrap().as_inline().unwrap().external_addressable);
            assert!(!definition.profiles.get(&ProfileName::from(installed::PRIVATE_HELPER_PROFILE))
                .unwrap().as_inline().unwrap().external_addressable);
            let selected = fixture.lifetime().selected_policy().native_host.as_ref().unwrap();
            let compiled_helper = selected.members.iter()
                .find(|member| member.member.member == installed::HELPER).unwrap();
            assert_eq!(compiled_helper.member.role, installed::PRIVATE_HELPER_PROFILE);
            assert!(handle.effective_member_profile(&original_member).await.unwrap().external_addressable);
            assert!(!handle.effective_member_profile(&helper_member).await.unwrap().external_addressable);
            assert_eq!(fixture.model_requests(), 0);
            let public_helper = handle.member(&helper_member).await.unwrap();
            match public_helper.send("public helper ingress must refuse", meerkat_core::types::HandlingMode::Queue).await {
                Err(meerkat_mob::MobError::NotExternallyAddressable(identity)) => assert_eq!(identity, helper_member),
                Err(error) => panic!("expected exact public helper addressability refusal: {error}"),
                Ok(_) => panic!("public external work entered the private helper"),
            }
            assert!(acquisition_approved::native_history(history.as_ref(), &helper_session).await.is_empty());
            assert_eq!(fixture.runtime.completion_cursor(&helper).await, helper_before);
            assert_eq!(fixture.model_requests(), 0, "public refusal must not enter a model");
            let (_prepared, parent) = acquisition_approved::select_reviewed_setup(&fixture).await;
            let first = fixture.submit().await;
            let Ok(PrivateOriginalSubmission::Admitted {
                input_id: original_input,
                turn_ticket: Some(_),
                deduplicated: false,
                source_settlement: PrivateSourceSettlement::FreshAcceptancePromoted,
                ..
            }) = &first
            else {
                panic!(
                    "real A input admission required: {}",
                    submission_context(&first)
                )
            };
            script.first_response_waiting().await;
            let binding = fixture.binding().await.unwrap().unwrap();
            let WorkAuthorityBasis::GrantLineage { lineage } = &binding.candidate().authority_basis
            else {
                panic!("actual reviewed setup source authority")
            };
            assert_eq!(&lineage[..1], parent.as_slice());
            retain_actual_a_login(&fixture, &binding, &login);
            assert!(fixture.source.helper_sources.lock().unwrap().is_empty());
            script.release_first_response();
            fault.entered.notified().await;
            // This is after actual issuance, source publication and helper binding.
            let held = issued_helper(&fixture, &helper_session, &binding).await;
            let helper_input = fault.helper_input.lock().unwrap().clone().unwrap();
            assert_ne!(helper_input.to_string(), *original_input);
            let saved_helper = held.source_record().as_ref().clone();
            let mut retirement = logins.fixture_retire(1).unwrap();
            assert!(
                login.check().is_err(),
                "retirement has published its local fence"
            );
            if matches!(mode, DeliveryMode::HoldHelperBeforeLookup) {
                assert_eq!(fault.helper_returns.load(Ordering::SeqCst), 0);
                assert_eq!(fault.accepted.load(Ordering::SeqCst), 0);
                assert!(
                    acquisition_approved::native_history(history.as_ref(), &helper_session)
                        .await
                        .is_empty()
                );
                // Issuance is over and final entry has not reserved. Retirement must
                // drain before the native lookup/admission operation is released.
                let retired = (&mut retirement).await.unwrap();
                assert!(retired.fenced && retired.reservations_drained && !retired.uncertain);
                fault.release.add_permits(1);
                fixture.finish(&first).await.unwrap();
                assert_eq!(fault.helper_returns.load(Ordering::SeqCst), 1);
                assert_eq!(
                    fault.accepted.load(Ordering::SeqCst),
                    0,
                    "retirement after bind must refuse before actual helper admission"
                );
                let reply = tool_reply(&script);
                assert_eq!(reply["created"], true);
                assert_eq!(
                    reply["worker"]["state"], "native_outcome_unavailable",
                    "{reply}"
                );
                assert!(
                    acquisition_approved::native_history(history.as_ref(), &helper_session)
                        .await
                        .is_empty()
                );
                assert_eq!(
                    fixture.runtime.completion_cursor(&helper).await,
                    helper_before
                );
                assert_eq!(
                    fixture.model_requests(),
                    2,
                    "A tool call and answer, no helper model entry"
                );
            } else {
                assert!(matches!(mode, DeliveryMode::HoldHelperAcceptedReply));
                assert_eq!(fault.helper_returns.load(Ordering::SeqCst), 1);
                assert_eq!(fault.accepted.load(Ordering::SeqCst), 1);
                let rows =
                    acquisition_approved::native_history(history.as_ref(), &helper_session).await;
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].state.input_id, helper_input);
                assert_eq!(rows[0].state.authority_contributors.len(), 1);
                assert_eq!(
                    rows[0].state.authority_contributors[0].association(),
                    held.original().association()
                );
                // The real native admission already owns this operation. The entry
                // permit is retained by IdentityRuntime until the unchanged bridge
                // reply is observed. Retirement must not cancel accepted work.
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), &mut retirement)
                        .await
                        .is_err(),
                    "native permit remains outstanding until its owner observes settlement"
                );
                fault.release.add_permits(1);
                let retired = retirement.await.unwrap();
                assert!(retired.fenced && retired.reservations_drained && !retired.uncertain);
                fixture.finish(&first).await.unwrap();
                let reply = tool_reply(&script);
                assert_eq!(reply["created"], true);
                assert_eq!(reply["worker"]["state"], "input_admitted", "{reply}");
                assert_eq!(reply["worker"]["deduplicated"], false);
                assert_eq!(
                    reply["worker"]["source_settlement"],
                    "fresh_acceptance_promoted"
                );
                let helper_after = fixture
                    .runtime
                    .wait_for_completion(&helper, helper_before, WAIT)
                    .await
                    .unwrap();
                assert_ne!(helper_after, helper_before);
                let consumed = acquisition_approved::consumed_native_input(
                    history.as_ref(),
                    &helper_session,
                    held.original().association(),
                    Some(&helper_input.to_string()),
                    deadline,
                )
                .await;
                assert_eq!(consumed.state.input_id, helper_input);
                assert_eq!(fault.accepted.load(Ordering::SeqCst), 1);
                assert_eq!(
                    fixture.model_requests(),
                    3,
                    "A call/answer and the same accepted helper turn"
                );
            }
            acquisition_approved::consumed_native_input(
                history.as_ref(),
                &fixture.session,
                &binding,
                Some(original_input),
                deadline,
            )
            .await;
            assert_eq!(fixture.binding().await.unwrap(), Some(binding));
            assert_eq!(
                fixture.store.get(&saved_helper.key).await.unwrap().unwrap(),
                saved_helper
            );
            assert_eq!(fixture.source.helper_sources.lock().unwrap().len(), 1);
            // Retirement does not revoke the controller grant or change canonical
            // source selection. The final fence is the discriminating boundary.
            issued_helper(
                &fixture,
                &helper_session,
                &fixture.binding().await.unwrap().unwrap(),
            )
            .await;
        }),
    ))
    .catch_unwind()
    .await;
    // Release only mechanical gates on every failure path, then join the
    // existing runtime shutdown. Never synthesize an admission or settlement.
    script.release_first_response();
    fault.release.add_permits(1);
    let cleanup = fixture.shutdown().await;
    assert!(cleanup.is_ok(), "{cleanup:?}");
    match checked {
        Ok(Ok(())) => {}
        Ok(Err(_)) => panic!("actual helper entry control timed out"),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_contributor_after_issuance_refuses_actual_helper_final_entry() {
    Box::pin(exercise(DeliveryMode::HoldHelperBeforeLookup)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entered_helper_keeps_same_login_until_native_settlement_is_observed() {
    Box::pin(exercise(DeliveryMode::HoldHelperAcceptedReply)).await;
}
