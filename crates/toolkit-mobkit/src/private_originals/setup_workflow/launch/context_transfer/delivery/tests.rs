//! Actual task-custody mechanics only. This control claims no native admission,
//! completed transfer, store nonapplication or recipient authorization.
use super::*;
use futures::FutureExt;
use std::{panic::AssertUnwindSafe, time::Duration};

#[tokio::test]
async fn cancelled_delivery_observer_retains_and_joins_the_same_task() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let ended = Arc::new(AtomicBool::new(false));
    let task_entered = entered.clone();
    let task_release = release.clone();
    let task_ended = ended.clone();
    let started = entered.notified();
    tokio::pin!(started);
    started.as_mut().enable();
    let task = tokio::spawn(async move {
        task_entered.notify_one();
        task_release.notified().await;
        task_ended.store(true, Ordering::Release);
        Ok(WorkflowDeliveryObservation::Pending)
    });
    let run = Arc::new(DeliveryRun {
        join: tokio::sync::Mutex::new(DeliveryJoin::Running(task)),
        native: Arc::new(Mutex::new(None)), joined: AtomicBool::new(false),
    });
    let checked = AssertUnwindSafe(async {
        tokio::time::timeout(Duration::from_secs(1), started).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(10), run.join()).await.is_err());
        assert!(!run.joined.load(Ordering::Acquire));
        assert!(!ended.load(Ordering::Acquire));
        assert!(!run.finished());
    }).catch_unwind().await;
    // Release and join even when the observer assertion panics. No test exit
    // drops an entered child and pretends the cancellation joined it.
    release.notify_one();
    let outcome = tokio::time::timeout(Duration::from_secs(1), run.join()).await.unwrap().unwrap();
    assert!(ended.load(Ordering::Acquire));
    assert!(run.joined.load(Ordering::Acquire));
    assert!(run.finished());
    assert_eq!(outcome, WorkflowDeliveryObservation::Pending);
    assert_eq!(run.join().await.unwrap(), outcome);
    if let Err(panic) = checked { std::panic::resume_unwind(panic); }
}

/// The absence witness is controlled at the native-read boundary; this test
/// does not manufacture native nonadmission. It uses the production retained
/// run registrar and actual SQLite claims to prove that a delayed old observer
/// cannot overlap a newer claim, including after that newer lease expires.
#[tokio::test]
async fn old_absence_observer_cannot_reset_a_newer_delivery_claim() {
    use toolkit_store::{AdmissionRequest, EffectKey, SqliteStore, StoreKey, ToolkitStore};
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteStore::open(directory.path().join("delivery.sqlite")).unwrap());
    let record = StoreKey { realm: "delivery-test".into(), owner: "slot".into(), id: "one".into() };
    let data = RecordData { schema: "test.delivery-order".into(), version: 1,
        body: serde_json::json!({"controlled_absence":true}) };
    store.admit(AdmissionRequest {
        key: record.clone(), admission_key: "delivery-one".into(), data: data.clone(), events: vec![],
        effects: vec![EffectIntent { id: "input".into(), kind: "test.delivery".into(),
            request: data.clone(), idempotency_key: "one-input".into(),
            replay_safety: ReplaySafety::ReconcileBeforeRetry }],
    }).await.unwrap();
    let key = EffectKey { record, id: "input".into() };
    let EffectClaimOutcome::Claimed(first) = store.claim_effect(&key, 1, "first", 60_000).await.unwrap()
        else { panic!("first claim") };
    store.acknowledge_effect(&first.lease.unwrap(), EffectOutcome::Uncertain { evidence: data.clone() })
        .await.unwrap();
    let absence_read = Arc::new(tokio::sync::Notify::new());
    let release_old = Arc::new(tokio::sync::Notify::new());
    let retry_claimed = Arc::new(tokio::sync::Notify::new());
    let release_retry = Arc::new(tokio::sync::Notify::new());
    let retry_ready = Arc::new(AtomicBool::new(false));
    let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let current = Mutex::new(None);
    let old = {
        let store = store.clone(); let key = key.clone(); let data = data.clone();
        let read = absence_read.clone(); let release = release_old.clone(); let ready = retry_ready.clone();
        DeliveryRun::retain_or_start(&mut current.lock().unwrap(), move |_| async move {
            let effect = store.get_effect(&key).await.unwrap().unwrap();
            assert_eq!(effect.attempt, 1);
            assert_eq!(effect.status, EffectStatus::Uncertain);
            read.notify_one();
            release.notified().await;
            let claim = store.claim_reconciliation(&key, "old-observer", 60_000).await.unwrap();
            assert_eq!(claim.attempt, 1);
            store.reconcile_effect(&claim.lease.unwrap(),
                Reconciliation::NotApplied { evidence: data }).await.unwrap();
            ready.store(true, Ordering::Release);
            Ok(WorkflowDeliveryObservation::NotApplied)
        })
    };
    let checked = AssertUnwindSafe(async {
        tokio::time::timeout(Duration::from_secs(1), absence_read.notified()).await.unwrap();
        let calls = starts.clone();
        let competing = DeliveryRun::retain_or_start(&mut current.lock().unwrap(), move |_| {
            calls.fetch_add(1, Ordering::AcqRel);
            async { Ok(WorkflowDeliveryObservation::Pending) }
        });
        assert!(Arc::ptr_eq(&competing, &old));
        assert_eq!(starts.load(Ordering::Acquire), 0, "no retry starts behind an unjoined absence read");
        assert_eq!(store.get_effect(&key).await.unwrap().unwrap().attempt, 1);
        assert!(!retry_ready.load(Ordering::Acquire));
        release_old.notify_one();
        assert_eq!(tokio::time::timeout(Duration::from_secs(1), old.join()).await.unwrap().unwrap(),
            WorkflowDeliveryObservation::NotApplied);
        assert!(retry_ready.load(Ordering::Acquire));
        let retry = {
            let store = store.clone(); let key = key.clone(); let calls = starts.clone();
            let ready = retry_ready.clone(); let claimed = retry_claimed.clone(); let release = release_retry.clone();
            DeliveryRun::retain_or_start(&mut current.lock().unwrap(), move |_| async move {
                calls.fetch_add(1, Ordering::AcqRel);
                ready.store(false, Ordering::Release);
                let EffectClaimOutcome::Claimed(claim) = store.claim_effect(&key, 1, "retry", 1).await.unwrap()
                    else { panic!("new attempt after joined nonapplication") };
                assert_eq!(claim.attempt, 2);
                claimed.notify_one();
                release.notified().await;
                Ok(WorkflowDeliveryObservation::Pending)
            })
        };
        assert!(!Arc::ptr_eq(&retry, &old));
        tokio::time::timeout(Duration::from_secs(1), retry_claimed.notified()).await.unwrap();
        let newer = store.get_effect(&key).await.unwrap().unwrap();
        let expiry = newer.lease.as_ref().unwrap().expires_at_ms;
        tokio::time::timeout(Duration::from_secs(1), async {
            while store.now_ms().await.unwrap() <= expiry {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }).await.unwrap();
        assert_eq!(old.join().await.unwrap(), WorkflowDeliveryObservation::NotApplied);
        assert!(!retry_ready.load(Ordering::Acquire), "joined old result cannot reset new attempt readiness");
        assert_eq!(store.get_effect(&key).await.unwrap().unwrap(), newer,
            "expired newer claim cannot be reconciled by the old witness");
        let calls = starts.clone();
        let third = DeliveryRun::retain_or_start(&mut current.lock().unwrap(), move |_| {
            calls.fetch_add(1, Ordering::AcqRel);
            async { Ok(WorkflowDeliveryObservation::Pending) }
        });
        assert!(Arc::ptr_eq(&third, &retry));
        assert_eq!(starts.load(Ordering::Acquire), 1);
    }).catch_unwind().await;
    // All real tasks remain owned and are joined on both success and panic.
    release_old.notify_one(); release_retry.notify_one();
    let latest = current.lock().unwrap().clone();
    let _ = tokio::time::timeout(Duration::from_secs(1), old.join()).await.unwrap();
    if let Some(latest) = latest {
        let _ = tokio::time::timeout(Duration::from_secs(1), latest.join()).await.unwrap();
    }
    if let Err(panic) = checked { std::panic::resume_unwind(panic); }
}

/// The actual pre-dispatch store observation lives inside the outer advance,
/// before an inner delivery slot or native input is required. No recipient or
/// native admission is fabricated by this task/store ownership control.
#[tokio::test]
async fn slow_advance_observation_survives_two_polls_without_blocking_another() {
    use crate::installed_host::acquisition::recovery::AcquisitionRecovery;
    use toolkit_store::{AdmissionRequest, SqliteStore, StoreKey, ToolkitStore};
    use std::sync::atomic::AtomicUsize;
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteStore::open(directory.path().join("advance.sqlite")).unwrap());
    let key = StoreKey { realm: "advance-test".into(), owner: "observation".into(), id: "one".into() };
    let data = RecordData { schema: "test.advance-observation".into(), version: 1,
        body: serde_json::json!({"retained":true}) };
    store.admit(AdmissionRequest { key: key.clone(), admission_key: "one".into(), data: data.clone(),
        events: vec![], effects: vec![] }).await.unwrap();
    let lifecycle = AcquisitionRecovery::default();
    let control = lifecycle.transfer_control();
    let current = Mutex::new(None);
    let competing = Mutex::new(None);
    let entered = Arc::new(AtomicUsize::new(0));
    let reads = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let reached = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let first = {
        let store = store.clone(); let key = key.clone(); let data = data.clone();
        let entered = entered.clone(); let reads = reads.clone(); let finished = finished.clone();
        let reached = reached.clone(); let release = release.clone();
        DeliveryRun::register_advance(&control, &current, move || async move {
            entered.fetch_add(1, Ordering::AcqRel);
            let row = store.get(&key).await.unwrap().unwrap();
            assert_eq!(row.data, data);
            reads.fetch_add(1, Ordering::AcqRel);
            reached.notify_one();
            // Hold the completed canonical observation before delivery entry.
            release.notified().await;
            finished.fetch_add(1, Ordering::AcqRel);
            Ok(WorkflowDeliveryObservation::Pending)
        }).unwrap()
    };
    let checked = AssertUnwindSafe(async {
        tokio::time::timeout(Duration::from_secs(1), reached.notified()).await.unwrap();
        for _ in 0..2 {
            let later = DeliveryRun::register_advance(&control, &current, || async {
                panic!("a later poll restarted the pre-delivery observation")
            }).unwrap();
            assert!(Arc::ptr_eq(&first, &later));
            assert!(tokio::time::timeout(Duration::from_millis(10), later.join()).await.is_err());
            assert_eq!(entered.load(Ordering::Acquire), 1);
            assert_eq!(reads.load(Ordering::Acquire), 1);
            assert_eq!(finished.load(Ordering::Acquire), 0);
        }
        let other = {
            let store = store.clone(); let key = key.clone(); let data = data.clone();
            DeliveryRun::register_advance(&control, &competing, move || async move {
                assert_eq!(store.get(&key).await.unwrap().unwrap().data, data);
                Err(PrivateOriginalError::Conflict)
            }).unwrap()
        };
        assert_eq!(tokio::time::timeout(Duration::from_secs(1), other.join()).await.unwrap(),
            Err(PrivateOriginalError::Conflict), "another observation and its typed result are independent");
        assert_eq!(finished.load(Ordering::Acquire), 0);
        lifecycle.stop();
        assert!(matches!(DeliveryRun::register_advance(&control, &Mutex::new(None), || async {
            panic!("registration after stop")
        }), Err(PrivateOriginalError::Unavailable)));
    }).catch_unwind().await;
    // Retain and join both real task owners even when any assertion fails.
    lifecycle.stop();
    release.notify_one();
    assert_eq!(tokio::time::timeout(Duration::from_secs(1), first.join()).await.unwrap().unwrap(),
        WorkflowDeliveryObservation::Pending);
    let other = competing.lock().unwrap().clone();
    if let Some(other) = other { let _ = tokio::time::timeout(Duration::from_secs(1), other.join()).await.unwrap(); }
    assert_eq!(entered.load(Ordering::Acquire), 1);
    assert_eq!(reads.load(Ordering::Acquire), 1);
    assert_eq!(finished.load(Ordering::Acquire), 1);
    lifecycle.join().await.unwrap();
    if let Err(panic) = checked { std::panic::resume_unwind(panic); }
}
