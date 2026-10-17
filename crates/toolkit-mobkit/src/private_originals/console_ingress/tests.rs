//! Mechanical stock-input selection plus the actual governed native binder.
//! The original control below covers the binder only. verifier_tests extends
//! this same installed fixture through the actual configured Console HTTP route.
use super::*;
use crate::private_originals::ContinuationFixture;
use futures::FutureExt;
use meerkat_mobkit::identity_first::{TurnOutcome, TurnOutput, TurnTracking};
use meerkat_runtime::PromptInput;
use std::{panic::AssertUnwindSafe, time::Duration};

const STOCK_KEY: &str =
    "console:00000000-0000-4000-8000-000000000001:00000000-0000-4000-8000-000000000002";
const WAIT: Duration = Duration::from_secs(20);

#[test]
fn stock_console_key_is_required_and_preserved_without_input_mutation() {
    let mut prompt = PromptInput::new("retained Console content", None);
    let input = Input::Prompt(prompt.clone());
    assert!(stock_console_event_key(&input).is_err());
    prompt.header.idempotency_key = Some(IdempotencyKey::new(STOCK_KEY));
    let input = Input::Prompt(prompt);
    let before = canonical_json(&input).unwrap();
    assert_eq!(
        stock_console_event_key(&input).unwrap(),
        IdempotencyKey::new(STOCK_KEY)
    );
    assert_eq!(canonical_json(&input).unwrap(), before);
}

struct ObserveBoundInput {
    inner: Arc<OriginalBinder>,
    observed: Mutex<Option<Input>>,
}
#[async_trait::async_trait]
impl GovernedInputBinder for ObserveBoundInput {
    async fn bind(
        &self,
        context: &GovernedBindContext,
        input: Input,
    ) -> Result<BoundGovernedInput, String> {
        let bound = self.inner.bind(context, input).await?;
        *self
            .observed
            .lock()
            .map_err(|_| "Input observation unavailable")? = Some(bound.input.clone());
        Ok(bound)
    }
    fn retain_unresolved(&self, settlement: Box<dyn GovernedSettlement>, detail: &str) {
        self.inner.retain_unresolved(settlement, detail);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_original_binding_preserves_stock_console_key_and_exact_replay() {
    let fixture = ContinuationFixture::for_service_input().await;
    let result = AssertUnwindSafe(Box::pin(async {
        let mut prompt = PromptInput::new("Answer this retained input", None);
        prompt.header.idempotency_key = Some(IdempotencyKey::new(STOCK_KEY));
        let raw = Input::Prompt(prompt);
        let raw_id = raw.id().clone();
        let raw_bytes = canonical_json(&raw).unwrap();
        let event_key = stock_console_event_key(&raw).unwrap();
        let mut event = crate::original_ingress::tests::private_event("stock-console-key");
        event.route = Id::new("console").unwrap();
        event.original = EvidenceId::new(raw_id.to_string()).unwrap();
        event.occurrence = event.original.clone();
        event.content_sha256 = digest(&raw_bytes);
        let authentication = event.original_authentication.clone();
        let original = fixture.source.retain_event(event).await.unwrap();
        let route = fixture.source.route(&original.route).unwrap().clone();
        let private_key = fixture.source.original_event_key(&original).await.unwrap();
        assert_ne!(
            private_key, event_key,
            "fixture must distinguish private occurrence and Console keys"
        );
        let runtime = fixture.source.bound_identity_runtime().unwrap();
        let identity = runtime
            .owned_identity_for_member_alias(route.grant_target.as_str())
            .await
            .unwrap();
        let make_binder = || {
            Arc::new(ObserveBoundInput {
                inner: Arc::new(OriginalBinder {
                    source: fixture.source.clone(),
                    grant: None, batch: None,
                    original: original.clone(),
                    held: OnceLock::new(),
                    pending: OnceLock::new(),
                    authentication: evidence(&route.authentication_domain, &authentication)
                        .unwrap(),
                    event_key: event_key.clone(),
                    console: None,
                    approved_login: None,
                }),
                observed: Mutex::new(None),
            })
        };
        let first_binder = make_binder();
        let first = tokio::time::timeout(
            WAIT,
            runtime.send_governed_with_turn_ticket(
                &identity,
                Some(route.grant_target.as_str()),
                raw.clone(),
                first_binder.clone(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(first.admission.session_id, fixture.session);
        assert_eq!(first.admission.input_id, raw_id);
        assert!(!first.admission.deduplicated);
        assert!(first.settlement.is_ok());
        let bound = first_binder.observed.lock().unwrap().clone().unwrap();
        assert_eq!(bound.id(), &raw_id);
        assert_eq!(bound.header().idempotency_key.as_ref(), Some(&event_key));
        assert!(bound.header().authority_association.is_some());
        let TurnTracking::Tracked(ticket) = first.ticketed.turn else {
            panic!("native ticket missing")
        };
        let completed = tokio::time::timeout(WAIT, runtime.wait_for_turn(&identity, ticket, WAIT))
            .await
            .unwrap();
        assert!(matches!(
            completed,
            TurnOutcome::Completed {
                output: TurnOutput::Text { .. }
            }
        ));
        let requests = fixture.model_requests();
        assert!(requests > 0);

        let replay_binder = make_binder();
        let replay = tokio::time::timeout(
            WAIT,
            runtime.send_governed_with_turn_ticket(
                &identity,
                Some(route.grant_target.as_str()),
                raw.clone(),
                replay_binder.clone(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(replay.admission.input_id, raw_id);
        assert!(replay.admission.deduplicated);
        assert!(replay.settlement.is_ok());
        let replayed = replay_binder.observed.lock().unwrap().clone().unwrap();
        assert_eq!(replayed.id(), &raw_id);
        assert_eq!(replayed.header().idempotency_key.as_ref(), Some(&event_key));
        assert_eq!(
            replayed.header().authority_association,
            bound.header().authority_association
        );
        let TurnTracking::Tracked(replay_ticket) = replay.ticketed.turn else {
            panic!("native replay ticket missing")
        };
        let replay_completed =
            tokio::time::timeout(WAIT, runtime.wait_for_turn(&identity, replay_ticket, WAIT))
                .await
                .unwrap();
        assert!(matches!(
            replay_completed,
            TurnOutcome::Completed {
                output: TurnOutput::Text { .. }
            }
        ));
        assert_eq!(fixture.model_requests(), requests);
        assert_eq!(canonical_json(&raw).unwrap(), raw_bytes);
        assert_eq!(
            fixture.source.original_event_key(&original).await.unwrap(),
            private_key
        );
    }))
    .catch_unwind()
    .await;
    let cleanup = fixture.shutdown().await;
    assert!(cleanup.is_ok(), "native cleanup failed: {cleanup:?}");
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

#[path = "verifier_tests.rs"]
mod verifier_tests;
