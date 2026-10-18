//! Deliver a completed transfer through the existing G/P native input owner.
//! The live transfer attempt retains one Input, including its generated ID.
//! Store leases, missing rows and departed donors cannot manufacture entry.
use super::*;
use crate::original_ingress::{PendingToolkitOriginal, shared_entry::SharedEntry};
use meerkat_authorization_contracts::evidence::HistoricalEvidenceRef;
use meerkat_core::{SessionId, lifecycle::InputId};
use meerkat_mobkit::identity_first::{AgentAddressability, GovernedAdmission};
use meerkat_runtime::{SessionServiceRuntimeExt, identifiers::IdempotencyKey,
    input_state::verify_exact_replay};
use toolkit_store::{EffectIntent, ReplaySafety, StoredEffect};

#[cfg(test)]
mod tests;

const RECEIPT_SCHEMA: &str = "toolkit.workflow-context-input";

/// Native input admission only. This neither completes a G turn nor settles
/// any waiter's installation, result or business effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowDeliveryObservation {
    Pending,
    /// The previous owned attempt joined without admission. A later call must
    /// acquire fresh G/P and workflow authority before using the same input.
    NotApplied,
    Admitted { session_id: String, input_id: String },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryReceipt {
    admission: WorkAdmission,
    membership: SetupWorkflowWaiter,
    session: SessionId,
    input: InputId,
    association: InputAuthorityAssociation,
}

/// Only the existing transfer attempt owns this slot. It is not a durable
/// reconstruction recipe and has no payload getter or serialization.
pub(super) struct DeliverySlot {
    input: Input,
    event: IdempotencyKey,
    workflow: Arc<HeldSetupWorkflow>,
    bound: OnceLock<Input>,
    run: Mutex<Option<Arc<DeliveryRun>>>,
    native: Mutex<Option<Arc<DeliveryNative>>>,
    retry_ready: AtomicBool,
}

pub(super) struct DeliveryRun {
    join: tokio::sync::Mutex<DeliveryJoin>,
    native: Arc<Mutex<Option<Arc<DeliveryNative>>>>,
    joined: AtomicBool,
}
enum DeliveryJoin {
    Running(tokio::task::JoinHandle<Result<WorkflowDeliveryObservation, PrivateOriginalError>>),
    Joined(Result<WorkflowDeliveryObservation, PrivateOriginalError>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NativeDecision { NeverSubmitted, Submitted, NotAdmitted, Accepted }

struct DeliveryNative {
    decision: Mutex<NativeDecision>,
    joined: AtomicBool,
    custody: Arc<DeliveryCustody>,
}
#[derive(Default)]
struct DeliveryCustody {
    pending: Mutex<Option<PendingToolkitOriginal>>,
    unresolved: Mutex<Vec<Box<dyn GovernedSettlement>>>,
    accepted: OnceLock<GovernedAdmission>,
    entry: OnceLock<Arc<SharedEntry>>,
}

impl InstalledWorkflowContext {
    /// At most one owned attempt per call. Caller loss leaves the actual task
    /// in the transfer's recovery owner. No call reconstructs a new Input ID.
    pub async fn deliver(&self) -> Result<WorkflowDeliveryObservation, PrivateOriginalError> {
        let source = self.transfer.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let slot = self.transfer.with_recipient(&source, |workflow| {
            if !Arc::ptr_eq(&workflow, &self.workflow) {
                return Err(PrivateOriginalError::Conflict);
            }
            let mut held = self.attempt.delivery.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            if let Some(slot) = held.as_ref() { return Ok(slot.clone()); }
            let bytes = canonical_json(&self.attempt.envelope).map_err(|_| PrivateOriginalError::Conflict)?;
            let input = Input::Prompt(PromptInput::new(
                String::from_utf8(bytes).map_err(|_| PrivateOriginalError::Conflict)?, None));
            let key = self.attempt.envelope.membership.delivery_effect()
                .map_err(|_| PrivateOriginalError::Conflict)?;
            let slot = Arc::new(DeliverySlot {
                input, event: IdempotencyKey::new(format!("workflow-context-{}",
                    digest(&canonical_json(&(&key, &self.attempt.admission))
                        .map_err(|_| PrivateOriginalError::Conflict)?))),
                workflow, bound: OnceLock::new(), run: Mutex::new(None), native: Mutex::new(None),
                retry_ready: AtomicBool::new(false),
            });
            *held = Some(slot.clone());
            Ok(slot)
        }).await?;
        slot.execute(source, self.transfer.clone(), self.attempt.clone(), true).await
    }
}

impl InstalledWorkflowContextTransfer {
    /// Metadata-only reconciliation of an already entered delivery. It may
    /// acknowledge an exact accepted input after recipient closure, but never
    /// exposes payload or submits anything, even if it proves nonadmission.
    pub async fn reconcile_delivery(self: &Arc<Self>) -> Result<WorkflowDeliveryObservation, PrivateOriginalError> {
        let source = self.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let original = self.original.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        // As in observe, an equal producer handle can be noncanonical. Resolve
        // the first retained selection before looking for its attempt or slot.
        let retained = source.retained_workflow_context_transfer(&original, &self.selected.correlation)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        if !same_transfer(Some(&retained), Some(self))? { return Err(PrivateOriginalError::Conflict); }
        let attempt = retained.attempt.lock().map_err(|_| PrivateOriginalError::Unavailable)?.clone();
        let Some(attempt) = attempt else { return Ok(WorkflowDeliveryObservation::Pending); };
        let slot = attempt.delivery.lock().map_err(|_| PrivateOriginalError::Unavailable)?.clone();
        let Some(slot) = slot else { return Ok(WorkflowDeliveryObservation::Pending); };
        // The private retained handle identifies the existing host owner. No
        // A-current check, open-recipient check or new native authorization is
        // needed to record that its exact old input was already admitted.
        source.host_lifetime.get().and_then(Weak::upgrade)
            .ok_or(PrivateOriginalError::Unavailable)?.validate_current_selection()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        slot.execute(source, retained, attempt, false).await
    }
}

impl DeliverySlot {
    async fn execute(self: &Arc<Self>, source: Arc<PrivateOriginals>,
        transfer: Arc<InstalledWorkflowContextTransfer>, attempt: Arc<TransferAttempt>,
        may_dispatch: bool) -> Result<WorkflowDeliveryObservation, PrivateOriginalError>
    {
        let control = attempt.recovery.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let run = control.enter_transfer(|| {
            let mut current = self.run.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            let slot = self.clone();
            Ok::<_, PrivateOriginalError>(DeliveryRun::retain_or_start(&mut current, move |task_native| async move {
                if may_dispatch {
                    slot.drive(&source, &transfer, &attempt, &task_native).await
                } else {
                    let effect = slot.effect(&source, &attempt).await?;
                    slot.reconcile(&source, &attempt, &effect).await
                }
            }))
        }).ok_or(PrivateOriginalError::Unavailable)??;
        run.join().await
    }

    async fn effect(&self, source: &PrivateOriginals, attempt: &TransferAttempt)
        -> Result<StoredEffect, PrivateOriginalError>
    {
        let membership = &attempt.envelope.membership;
        let key = membership.delivery_effect().map_err(|_| PrivateOriginalError::Conflict)?;
        let request = RecordData {
            schema: "meerkat_toolkit.setup_workflow.delivery".into(), version: 1,
            body: serde_json::json!({"workflow": membership.workflow(), "payload": membership}),
        };
        let expected = EffectIntent {
            id: key.id.clone(), kind: "setup_workflow_delivery".into(),
            idempotency_key: ContentDigest::of_bytes(&canonical_json(&request)
                .map_err(|_| PrivateOriginalError::Conflict)?).to_string(),
            request, replay_safety: ReplaySafety::ReconcileBeforeRetry,
        };
        let effect = source.store.get_effect(&key).await.map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        if effect.key != key || effect.intent != expected
            || effect.request_digest != expected.digest().map_err(store_error)? {
            return Err(PrivateOriginalError::Conflict);
        }
        Ok(effect)
    }

    fn receipt(&self, attempt: &TransferAttempt) -> Result<RecordData, PrivateOriginalError> {
        Ok(RecordData { schema: RECEIPT_SCHEMA.into(), version: 1,
            body: serde_json::to_value(DeliveryReceipt {
                admission: attempt.admission.clone(), membership: attempt.envelope.membership.clone(),
                session: self.workflow.session.clone(), input: self.input.id().clone(),
                association: self.workflow.planning.association().clone(),
            }).map_err(|_| PrivateOriginalError::Conflict)?,
        })
    }

    fn admitted(&self) -> WorkflowDeliveryObservation {
        WorkflowDeliveryObservation::Admitted { session_id: self.workflow.session.to_string(),
            input_id: self.input.id().to_string() }
    }

    async fn drive(self: &Arc<Self>, source: &Arc<PrivateOriginals>,
        transfer: &Arc<InstalledWorkflowContextTransfer>, attempt: &Arc<TransferAttempt>,
        owned_native: &Mutex<Option<Arc<DeliveryNative>>>)
        -> Result<WorkflowDeliveryObservation, PrivateOriginalError>
    {
        let effect = self.effect(source, attempt).await?;
        if effect.status != EffectStatus::Pending
            || (effect.attempt > 0 && !self.retry_ready.load(Ordering::Acquire)) {
            return self.reconcile(source, attempt, &effect).await;
        }
        transfer.with_recipient(source, |workflow| {
            if !Arc::ptr_eq(&workflow, &self.workflow) { return Err(PrivateOriginalError::Conflict); }
            Ok(())
        }).await?;
        let snapshot = source.workflow_store()?.load_setup_workflow(&transfer.selected.workflow)
            .await.map_err(|_| PrivateOriginalError::Unavailable)?;
        if snapshot.terms() != &transfer.planning.terms {
            return Err(PrivateOriginalError::Conflict);
        }
        // Validates exact historical membership; a committed donor may now be
        // departed. The final fence chooses any still-live recipient interest.
        let _ = snapshot.departed(&attempt.envelope.membership).map_err(|_| PrivateOriginalError::Conflict)?;
        let native = Arc::new(DeliveryNative {
            decision: Mutex::new(NativeDecision::NeverSubmitted), joined: AtomicBool::new(false),
            custody: Arc::new(DeliveryCustody::default()),
        });
        *owned_native.lock().map_err(|_| PrivateOriginalError::Unavailable)? = Some(native.clone());
        *self.native.lock().map_err(|_| PrivateOriginalError::Unavailable)? = Some(native.clone());
        // The retained task and NeverSubmitted witness exist before the store
        // await, including a committed claim whose response is lost.
        self.retry_ready.store(false, Ordering::Release);
        let claim = match source.store.claim_effect(&effect.key, snapshot.revision(),
            "installed-context-delivery", 60_000).await {
            Ok(EffectClaimOutcome::Claimed(claim)) => claim,
            Ok(EffectClaimOutcome::NeedsReconciliation(_))
            | Err(StoreError::Claimed | StoreError::Conflict | StoreError::EffectState) =>
                return Ok(WorkflowDeliveryObservation::Pending),
            Err(error) => return Err(store_error(error)),
        };
        let lease = claim.lease.ok_or(PrivateOriginalError::Unavailable)?;
        let route = source.route(&transfer.selected.planning_source.route)?;
        let controller = source.owner.workflow_controller(&self.workflow.planning).map_err(custody_error)?;
        let binder = Arc::new(DeliveryBinder {
            owner: source.owner.clone(), original: self.workflow.planning.clone(),
            slot: self.clone(), native: native.clone(), controller,
            authentication: evidence(&route.authentication_domain,
                &transfer.planning.submission.transport_authentication)?,
            planning: transfer.planning.clone(),
        });
        let runtime = source.bound_identity_runtime()?;
        let identity = runtime.owned_identity_for_member_alias(&self.workflow.member.member).await
            .ok_or(PrivateOriginalError::Unavailable)?;
        *native.decision.lock().map_err(|_| PrivateOriginalError::Unavailable)? = NativeDecision::Submitted;
        let result = runtime.dispatch_governed_with_turn_ticket(&identity,
            Some(&self.workflow.member.member), self.input.clone(), binder).await;
        let observation = match result {
            Ok(outcome) => {
                if outcome.admission.session_id != self.workflow.session
                    || outcome.admission.input_id != *self.input.id() {
                    return Err(PrivateOriginalError::Conflict);
                }
                *native.decision.lock().map_err(|_| PrivateOriginalError::Unavailable)? = NativeDecision::Accepted;
                // Native dedup is possible only for this exact retained Input.
                // It never promotes the retry; exact readback settles below.
                if outcome.settlement.is_ok() && !outcome.admission.deduplicated
                    && native.custody.accepted.get() == Some(&outcome.admission) {
                    self.admitted()
                } else { WorkflowDeliveryObservation::Pending }
            }
            Err(IdentityRuntimeError::GovernedInput(GovernedInputError::Bind(_)
                | GovernedInputError::Mob(_) | GovernedInputError::EntryRefused(_))) => {
                *native.decision.lock().map_err(|_| PrivateOriginalError::Unavailable)? = NativeDecision::NotAdmitted;
                // Selected Meta has joined its definite nonadmission decision
                // and withdrawn its settlement before returning these arms.
                native.custody.pending.lock().map_err(|_| PrivateOriginalError::Unavailable)?.take();
                WorkflowDeliveryObservation::Pending
            }
            Err(_) => WorkflowDeliveryObservation::Pending,
        };
        let receipt = self.receipt(attempt)?;
        let outcome = if matches!(observation, WorkflowDeliveryObservation::Admitted { .. }) {
            EffectOutcome::Succeeded { receipt }
        } else { EffectOutcome::Uncertain { evidence: receipt } };
        source.store.acknowledge_effect(&lease, outcome).await.map_err(store_error)?;
        Ok(observation)
    }

    async fn reconcile(&self, source: &PrivateOriginals, attempt: &TransferAttempt, effect: &StoredEffect)
        -> Result<WorkflowDeliveryObservation, PrivateOriginalError>
    {
        let receipt = self.receipt(attempt)?;
        if effect.status == EffectStatus::Succeeded {
            if effect.outcome.as_ref() != Some(&EffectOutcome::Succeeded { receipt }) {
                return Err(PrivateOriginalError::Conflict);
            }
            return Ok(self.admitted());
        }
        if effect.attempt == 0 || effect.status == EffectStatus::Failed {
            return Ok(WorkflowDeliveryObservation::Pending);
        }
        let native = self.native.lock().map_err(|_| PrivateOriginalError::Unavailable)?.clone();
        let Some(native) = native else { return Ok(WorkflowDeliveryObservation::Pending); };
        // A missing row is conclusive only after the actual dispatch owner
        // joined and only when it never submitted or got definite nonadmission.
        if !native.joined.load(Ordering::Acquire) { return Ok(WorkflowDeliveryObservation::Pending); }
        let row = source.machine()?.input_state(&self.workflow.session, self.input.id())
            .await.map_err(|_| PrivateOriginalError::Unavailable)?;
        let applied = if let Some(row) = row {
            let bound = self.bound.get().ok_or(PrivateOriginalError::Conflict)?;
            if row.state.input_id != *self.input.id() || verify_exact_replay(&row.state, bound).is_err() {
                return Err(PrivateOriginalError::Conflict);
            }
            // The retained G source is already Admitted. This settles only
            // this input's pending=false binding, without resetting that source.
            if let Some(pending) = native.custody.pending.lock()
                .map_err(|_| PrivateOriginalError::Unavailable)?.take() {
                pending.admit().map_err(custody_error)?;
            }
            native.custody.unresolved.lock().map_err(|_| PrivateOriginalError::Unavailable)?.clear();
            if let Some(entry) = native.custody.entry.get() { entry.settle().map_err(custody_error)?; }
            true
        } else {
            let decision = *native.decision.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            if !matches!(decision, NativeDecision::NeverSubmitted | NativeDecision::NotAdmitted)
                || !native.custody.unresolved.lock().map_err(|_| PrivateOriginalError::Unavailable)?.is_empty()
                || native.custody.pending.lock().map_err(|_| PrivateOriginalError::Unavailable)?.is_some()
                || native.custody.entry.get().is_some_and(|entry| !entry.settled()) {
                return Ok(WorkflowDeliveryObservation::Pending);
            }
            false
        };
        let claim = match source.store.claim_reconciliation(&effect.key, "installed-context-observe", 60_000).await {
            Ok(claim) => claim,
            Err(StoreError::Claimed | StoreError::EffectState | StoreError::Conflict) =>
                return Ok(if applied { self.admitted() } else { WorkflowDeliveryObservation::Pending }),
            Err(error) => return Err(store_error(error)),
        };
        let lease = claim.lease.ok_or(PrivateOriginalError::Unavailable)?;
        source.store.reconcile_effect(&lease, if applied { Reconciliation::Applied { receipt } }
            else { Reconciliation::NotApplied { evidence: receipt } }).await.map_err(store_error)?;
        if applied { Ok(self.admitted()) }
        else {
            self.retry_ready.store(true, Ordering::Release);
            Ok(WorkflowDeliveryObservation::NotApplied)
        }
    }

    pub(super) async fn join(&self, finished_only: bool) -> Result<(), PrivateOriginalError> {
        let run = self.run.lock().map_err(|_| PrivateOriginalError::Unavailable)?.clone();
        if let Some(run) = run {
            if !finished_only || run.finished() { let _ = run.join().await; }
        }
        Ok(())
    }
}

impl DeliveryRun {
    /// Register the automatic advance before its first async observation.
    /// This reuses the transfer's slot and the existing recovery stop boundary.
    pub(super) fn register_advance<F, Fut>(control: &RecoveryControl,
        current: &Mutex<Option<Arc<Self>>>, start: F) -> Result<Arc<Self>, PrivateOriginalError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<WorkflowDeliveryObservation, PrivateOriginalError>>
            + Send + 'static,
    {
        control.enter_transfer(|| {
            let mut current = current.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            Ok(Self::retain_or_start(&mut current, move |_| start()))
        }).ok_or(PrivateOriginalError::Unavailable)?
    }

    fn retain_or_start<F, Fut>(current: &mut Option<Arc<Self>>, start: F) -> Arc<Self>
    where
        F: FnOnce(Arc<Mutex<Option<Arc<DeliveryNative>>>>) -> Fut,
        Fut: std::future::Future<Output = Result<WorkflowDeliveryObservation, PrivateOriginalError>>
            + Send + 'static,
    {
        // This runs under the slot mutex and the recovery stop mutex. Dispatch
        // and metadata observation cannot outlive their serialization and
        // later reconcile an old witness against a newer effect attempt.
        if let Some(prior) = current.as_ref() {
            if !prior.joined.load(Ordering::Acquire) { return prior.clone(); }
        }
        let native = Arc::new(Mutex::new(None));
        let join = tokio::spawn(start(native.clone()));
        let run = Arc::new(Self { join: tokio::sync::Mutex::new(DeliveryJoin::Running(join)),
            native, joined: AtomicBool::new(false) });
        *current = Some(run.clone());
        run
    }

    pub(super) fn finished(&self) -> bool {
        self.join.try_lock().is_ok_and(|held| match &*held {
            DeliveryJoin::Running(task) => task.is_finished(), DeliveryJoin::Joined(_) => true,
        })
    }
    pub(super) async fn join(&self) -> Result<WorkflowDeliveryObservation, PrivateOriginalError> {
        let mut held = self.join.lock().await;
        let result = match &mut *held {
            DeliveryJoin::Running(task) => task.await.unwrap_or(Err(PrivateOriginalError::Unavailable)),
            DeliveryJoin::Joined(result) => result.clone(),
        };
        *held = DeliveryJoin::Joined(result.clone());
        if let Some(native) = self.native.lock().map_err(|_| PrivateOriginalError::Unavailable)?.as_ref() {
            native.joined.store(true, Ordering::Release);
        }
        self.joined.store(true, Ordering::Release);
        result
    }
}

struct DeliveryBinder {
    owner: Arc<ToolkitOriginalOwner>,
    original: Arc<RetainedToolkitOriginal>,
    slot: Arc<DeliverySlot>,
    native: Arc<DeliveryNative>,
    controller: ControllerModelClient,
    authentication: HistoricalEvidenceRef,
    planning: Arc<InstalledWorkflowPlanning>,
}
#[async_trait::async_trait]
impl GovernedInputBinder for DeliveryBinder {
    async fn bind(&self, context: &GovernedBindContext, input: Input) -> Result<BoundGovernedInput, String> {
        let incoming = context.controller.plain_facts().map_err(|_| "delivery controller unavailable")?.route_key();
        let retained = self.controller.plain_facts().map_err(|_| "delivery controller unavailable")?.route_key();
        if context.session_id != self.slot.workflow.session || incoming != retained
            || context.spec.addressability != AgentAddressability::InternalOnly
            || input.id() != self.slot.input.id() {
            return Err("delivery destination changed".into());
        }
        let (input, pending) = self.owner.bind_authenticated_input(&self.original, &context.session_id,
            input, self.slot.event.clone(), self.authentication.clone(), context.controller.clone())
            .map_err(|_| "delivery binding refused")?;
        let canonical = self.slot.bound.get_or_init(|| input.clone());
        if canonical_json(canonical).map_err(|_| "delivery input encoding refused")?
            != canonical_json(&input).map_err(|_| "delivery input encoding refused")? {
            return Err("delivery input binding changed".into());
        }
        let mut custody = self.native.custody.pending.lock().map_err(|_| "delivery custody unavailable")?;
        if custody.is_some() { return Err("delivery binder was already entered".into()); }
        *custody = Some(pending);
        drop(custody);
        Ok(BoundGovernedInput { input,
            settlement: Box::new(DeliverySettlement { custody: Arc::downgrade(&self.native.custody),
                session: context.session_id.clone(), input: self.slot.input.id().clone() }),
            entry_fence: Some(Arc::new(DeliveryFence { planning: self.planning.clone(),
                custody: self.native.custody.clone() })),
        })
    }
    fn retain_unresolved(&self, settlement: Box<dyn GovernedSettlement>, _: &str) {
        // Poison does not permit custody loss or a later nonadmission claim.
        self.native.custody.unresolved.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(settlement);
    }
}
struct DeliverySettlement { custody: Weak<DeliveryCustody>, session: SessionId, input: InputId }
impl GovernedSettlement for DeliverySettlement {
    fn accepted(self: Box<Self>, admission: &GovernedAdmission) -> Result<(), String> {
        if admission.deduplicated || admission.session_id != self.session || admission.input_id != self.input {
            return Err("delivery acknowledgement changed".into());
        }
        let custody = self.custody.upgrade().ok_or("delivery custody unavailable")?;
        let pending = custody.pending.lock().map_err(|_| "delivery custody unavailable")?.take()
            .ok_or("delivery custody already settled")?;
        pending.admit().map_err(|_| "delivery source settlement failed")?;
        custody.accepted.set(admission.clone()).map_err(|_| "delivery acknowledged twice".into())
    }
}

/// Same final local source-interest boundary as first launch, with this exact
/// attempt's entry retained for later native reconciliation. Never calls the
/// async recipient observer or reenters the native runtime from Meta's fence.
struct DeliveryFence { planning: Arc<InstalledWorkflowPlanning>, custody: Arc<DeliveryCustody> }
impl GovernedEntryFence for DeliveryFence {
    fn enter(&self) -> Result<Box<dyn GovernedEntryPermit>, GovernedEntryRefusal> {
        let source = self.planning.source.upgrade().ok_or_else(||
            GovernedEntryRefusal::Unavailable("delivery source unavailable".into()))?;
        let mut interests = self.planning.interests.lock().map_err(|_|
            GovernedEntryRefusal::Unavailable("delivery interests unavailable".into()))?;
        let now = source.owner.clock().now().map_err(|_|
            GovernedEntryRefusal::Unavailable("delivery clock unavailable".into()))?.unix_ms;
        if now >= self.planning.terms.deadline_ms { return Err(GovernedEntryRefusal::Expired); }
        let mut unavailable = false;
        for interest in interests.iter_mut() {
            if interest.closed || now >= interest.membership.deadline_ms() { continue; }
            match source.owner.enter_workflow_launch(&interest.original) {
                Ok(entry) => {
                    if self.custody.entry.set(entry.clone()).is_err() {
                        let _ = entry.settle();
                        return Err(GovernedEntryRefusal::Unavailable("delivery already entered".into()));
                    }
                    interest.entries.push(entry.clone());
                    return Ok(Box::new(DeliveryPermit { entry }));
                }
                Err(crate::original_ingress::OriginalWriterError::OperationCancelled) => continue,
                Err(_) => unavailable = true,
            }
        }
        if unavailable { Err(GovernedEntryRefusal::Unavailable("delivery waiter unavailable".into())) }
        else { Err(GovernedEntryRefusal::Retired) }
    }
}
struct DeliveryPermit { entry: Arc<SharedEntry> }
impl GovernedEntryPermit for DeliveryPermit {
    fn finish(self: Box<Self>, outcome: GovernedEntryOutcome) {
        if outcome != GovernedEntryOutcome::Uncertain { let _ = self.entry.settle(); }
    }
}
