//! Consume only the recorded final-departure obligation. This source owner
//! fences G and observes its exact input; it does not cancel an ambient run.
use super::*;
use meerkat_runtime::{
    SessionServiceRuntimeExt,
    input_state::verify_exact_replay,
    terminal_status::{InputTerminalReceiptRead, InteractionSelector},
};
use toolkit_store::{EffectClaimKind, StoredEffect};

const SCHEMA: &str = "toolkit.setup-workflow-close";
const CLOSE_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// Historical close evidence, not result delivery, installation retirement or
/// interaction-terminal publication. A pending observation permits no replay.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WorkflowCloseObservation {
    SourceFencedAndNotAdmitted,
    SourceFencedAndFinalized { session_id: String, input_id: String },
    Pending,
}

impl InstalledWorkflowPlanning {
    /// The existing host close/reconciliation caller uses this only after
    /// durable final departure. Passive expiry does not manufacture departure.
    /// Dropping this future leaves the same effect claim and source custody for
    /// reconciliation. It never submits G or infers nonadmission from absence.
    pub(crate) async fn observe_close(
        &self,
        reference: &SetupWorkflowRef,
    ) -> Result<WorkflowCloseObservation, PrivateOriginalError> {
        let source = self.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let snapshot = source.workflow_store()?.load_setup_workflow(reference)
            .await.map_err(|_| PrivateOriginalError::Unavailable)?;
        if snapshot.terms() != &self.terms || !snapshot.sealed()
            || snapshot.active_waiters() != 0
            || self.terms.planning_source != source.key(&self.submission.original)?
        {
            return Err(PrivateOriginalError::Denied);
        }
        let key = reference.close_effect();
        let effect = source.store.get_effect(&key).await.map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        check_intent(&effect, reference)?;
        if effect.status == EffectStatus::Succeeded {
            let Some(EffectOutcome::Succeeded { receipt }) = effect.outcome else {
                return Err(PrivateOriginalError::Conflict);
            };
            let observation = read_receipt(receipt)?;
            return if observation != WorkflowCloseObservation::Pending {
                Ok(observation)
            } else { Err(PrivateOriginalError::Conflict) };
        }
        let claim = if effect.status == EffectStatus::Pending && effect.attempt == 0 {
            match source.store.claim_effect(&key, snapshot.revision(),
                "installed-workflow-close", 60_000).await {
                Ok(EffectClaimOutcome::Claimed(claim)) => claim,
                Ok(EffectClaimOutcome::NeedsReconciliation(_))
                | Err(StoreError::Claimed | StoreError::Conflict | StoreError::EffectState) =>
                    return Ok(WorkflowCloseObservation::Pending),
                Err(error) => return Err(store_error(error)),
            }
        } else {
            match source.store.claim_reconciliation(&key,
                "installed-workflow-close-observe", 60_000).await {
                Ok(claim) => claim,
                Err(StoreError::Claimed) => return Ok(WorkflowCloseObservation::Pending),
                Err(error) => return Err(store_error(error)),
            }
        };
        let lease = claim.lease.ok_or(PrivateOriginalError::Unavailable)?;
        // This bounds this read/repair attempt, not the lifetime of G's run.
        // Pending cancellation and admitted native custody remain owned when
        // an await is dropped. A future caller must reconcile this same effect.
        let observation = tokio::time::timeout(CLOSE_BOUND,
            self.close_observation(&source, reference)).await
            .unwrap_or(Ok(WorkflowCloseObservation::Pending))?;
        let receipt = RecordData { schema: SCHEMA.into(), version: 1,
            body: serde_json::to_value(&observation).map_err(|_| PrivateOriginalError::Conflict)? };
        let pending = observation == WorkflowCloseObservation::Pending;
        match lease.kind {
            EffectClaimKind::Dispatch => {
                source.store.acknowledge_effect(&lease, if pending {
                    EffectOutcome::Uncertain { evidence: receipt }
                } else { EffectOutcome::Succeeded { receipt } }).await.map_err(store_error)?;
            }
            EffectClaimKind::Reconcile => {
                source.store.reconcile_effect(&lease, if pending {
                    Reconciliation::Pending { evidence: receipt }
                } else { Reconciliation::Applied { receipt } }).await.map_err(store_error)?;
            }
        }
        Ok(observation)
    }

    pub(super) async fn close_observation(
        &self,
        source: &Arc<PrivateOriginals>,
        reference: &SetupWorkflowRef,
    ) -> Result<WorkflowCloseObservation, PrivateOriginalError> {
        // Canonical final departure is already committed. Close every local
        // interest under the same lock as LaunchFence::enter, then release it
        // before source persistence or native reads. No new entry is created.
        let entries = {
            let mut interests = self.interests.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            let mut entries = Vec::new();
            for interest in interests.iter_mut() {
                if interest.membership.workflow() != reference {
                    return Err(PrivateOriginalError::Conflict);
                }
                interest.closed = true;
                for entry in &interest.entries {
                    entry.close().map_err(custody_error)?;
                    entries.push(entry.clone());
                }
            }
            entries
        };
        let record = source.validate_cancellation_source(&self.submission.original, None, None)
            .await.map_err(custody_error)?;
        let decoded = source.decode_stored(&record)?;
        let original = meerkat_authorization_contracts::work_association::OriginalWorkRef {
            authority: decoded.source.source_authority,
            work: decoded.event.original,
        };
        // Use the exact G source owner, not task-group or installation cleanup.
        // P and each waiter keep their own source/grants. This fences future
        // G operations but does not interrupt a model request already entered.
        source.owner.record_operation_cancelled(&decoded.source.realm, &original,
            |binding, prior| async move {
                source.validate_cancellation_source(&self.submission.original,
                    binding.as_ref(), prior.as_deref()).await
            },
            |record| source.persist_source_cancellation(record),
        ).await.map_err(custody_error)?;
        // This is actual admission-decision settlement, not runtime terminal.
        crate::original_ingress::ToolkitOriginalOwner::drain_shared_entries(entries)
            .await.map_err(custody_error)?;

        let launch = source.store.get_effect(&reference.launch_effect()).await.map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        if launch.status == EffectStatus::Failed {
            let Some(EffectOutcome::Failed { evidence }) = launch.outcome else {
                return Err(PrivateOriginalError::Conflict);
            };
            if evidence.schema != "toolkit.setup-workflow-launch" || evidence.version != 1 {
                return Err(PrivateOriginalError::Conflict);
            }
            return match serde_json::from_value::<WorkflowLaunchObservation>(evidence.body)
                .map_err(|_| PrivateOriginalError::Conflict)? {
                WorkflowLaunchObservation::NotAdmitted =>
                    Ok(WorkflowCloseObservation::SourceFencedAndNotAdmitted),
                _ => Err(PrivateOriginalError::Conflict),
            };
        }
        let held = source.retained.lock().map_err(|_| PrivateOriginalError::Unavailable)?
            .iter().find(|held| held.reference == self.submission.original).cloned();
        let Some(held) = held else { return Ok(WorkflowCloseObservation::Pending); };
        let Some(workflow) = held.setup_workflow.get() else {
            return Ok(WorkflowCloseObservation::Pending);
        };
        if workflow.reference != *reference || !Arc::ptr_eq(&workflow.planning, &held.original) {
            return Err(PrivateOriginalError::Conflict);
        }
        let pending = {
            let inputs = held.unresolved.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            if inputs.len() > 1 { return Err(PrivateOriginalError::Conflict); }
            inputs.first().cloned()
        };
        let Some(pending) = pending else { return Ok(WorkflowCloseObservation::Pending); };
        let (session, input) = pending.workflow_input(workflow)?;
        if session != workflow.session { return Err(PrivateOriginalError::Conflict); }
        let machine = source.machine()?;
        let Ok(Some(stored)) = machine.input_state(&session, input.id()).await else {
            return Ok(WorkflowCloseObservation::Pending);
        };
        if stored.state.input_id != *input.id() || verify_exact_replay(&stored.state, &input).is_err() {
            return Err(PrivateOriginalError::Conflict);
        }
        // This public native reader owns receipt finalization and batch facts.
        // No separate terminal read is used to authorize a later cancel call.
        // A receipt-less/coalesced input cannot prove its carried work ended.
        let Ok(Some(terminal)) = machine.input_terminal_receipt(&session,
            InteractionSelector::InputId(input.id().clone())).await else {
                return Ok(WorkflowCloseObservation::Pending);
            };
        if terminal.report.input_id() != input.id() { return Err(PrivateOriginalError::Conflict); }
        match terminal.report {
            InputTerminalReceiptRead::Finalized(_) =>
                Ok(WorkflowCloseObservation::SourceFencedAndFinalized {
                    session_id: session.to_string(), input_id: input.id().to_string(),
                }),
            _ => Ok(WorkflowCloseObservation::Pending),
        }
    }
}

fn check_intent(effect: &StoredEffect, reference: &SetupWorkflowRef) -> Result<(), PrivateOriginalError> {
    if effect.key != reference.close_effect() || effect.intent.id != "close"
        || effect.intent.kind != "setup_workflow_close"
        || effect.intent.request.schema != "meerkat_toolkit.setup_workflow.close"
        || effect.intent.request.version != 1
        || effect.intent.request.body != serde_json::json!({"workflow":reference,"payload":reference})
    { return Err(PrivateOriginalError::Conflict); }
    Ok(())
}

fn read_receipt(receipt: RecordData) -> Result<WorkflowCloseObservation, PrivateOriginalError> {
    if receipt.schema != SCHEMA || receipt.version != 1 { return Err(PrivateOriginalError::Conflict); }
    serde_json::from_value(receipt.body).map_err(|_| PrivateOriginalError::Conflict)
}

impl PrivateOriginals {
    /// The outer cancellation operation has already fenced and persisted the
    /// actual source set, including approved-task descendants. No source lock
    /// is retained across these reads. Conditional join commits make its census
    /// complete even when an earlier join reply/interest publication was lost.
    pub(in crate::private_originals) async fn depart_cancelled_workflows(
        &self,
        cancelled: &[Arc<StoredRecord>],
    ) -> Result<PrivateOriginalCancellation, PrivateOriginalError> {
        let selected = {
            let retained = self.retained.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            let mut selected: Vec<(toolkit_store::StoreKey, Arc<InstalledWorkflowPlanning>)> = Vec::new();
            for row in cancelled {
                let decoded = self.decode_stored(row)?;
                if !decoded.operation_cancelled { return Err(PrivateOriginalError::Conflict); }
                for held in retained.iter().filter(|held| self.key(&held.reference).ok().as_ref() == Some(&row.key)) {
                    let choices = held.workflow_selections.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
                    for choice in choices.iter() {
                        if let Some(planning) = &choice.selection {
                            if !selected.iter().any(|(key, prior)| key == &row.key && Arc::ptr_eq(prior, planning)) {
                                selected.push((row.key.clone(), planning.clone()));
                            }
                        }
                    }
                }
            }
            selected
        };
        let mut outcome = PrivateOriginalCancellation::OperationsCancelled;
        for (source_key, planning) in selected {
            let store = self.workflow_store()?;
            let reference = store.workflow_ref(&planning.terms).map_err(|_| PrivateOriginalError::Conflict)?;
            let snapshot = match store.load_setup_workflow(&reference).await {
                Ok(snapshot) => snapshot,
                Err(meerkat_toolkit::setup::SetupError::Store(StoreError::NotFound)) => continue,
                Err(_) => return Err(PrivateOriginalError::Unavailable),
            };
            for membership in snapshot.waiters_for_source(&source_key) {
                let departed = planning.depart_waiter(&membership).await?;
                if departed.sealed() && departed.active_waiters() == 0 {
                    // Source cancellation and this departure are durable. A
                    // missing receipt or failed close read/ack is cleanup still
                    // pending, not failure of the completed cancellation. The
                    // same close effect remains for the joined recovery owner.
                    if !matches!(planning.observe_close(&reference).await,
                        Ok(WorkflowCloseObservation::SourceFencedAndNotAdmitted
                            | WorkflowCloseObservation::SourceFencedAndFinalized { .. }))
                    { outcome = PrivateOriginalCancellation::OperationsCancelledCleanupPending; }
                }
            }
        }
        Ok(outcome)
    }
}


/// Private canonical source metadata for one existing recovery-worker page.
/// Rows and cursor are observations, not reconstructed workflow authority.
pub(crate) struct WorkflowCloseRecoveryPage {
    pub(crate) sources: Vec<StoredRecord>,
    pub(crate) next_after_id: Option<String>,
}

impl PrivateOriginals {
    pub(crate) async fn workflow_close_recovery_page(
        &self, after: Option<&str>, limit: u32,
    ) -> Result<WorkflowCloseRecoveryPage, PrivateOriginalError> {
        if !(1..=128).contains(&limit) { return Err(PrivateOriginalError::Denied); }
        self.service_input_host_current()?;
        let sources = self.store.list_records(&self.scope, after, limit).await.map_err(store_error)?;
        self.service_input_host_current()?;
        let next_after_id = if sources.len() == limit as usize {
            sources.last().map(|row| row.key.id.clone())
        } else { None };
        Ok(WorkflowCloseRecoveryPage { sources, next_after_id })
    }

    /// Reopen only an already cancelled canonical source. Missing live planning
    /// handles are never rebuilt from stored labels, and this path never launches
    /// G, grants an effect or interprets source cancellation as native completion.
    pub(crate) async fn reconcile_cancelled_workflow_source(
        &self, observed: &StoredRecord,
    ) -> Result<PrivateOriginalCancellation, PrivateOriginalError> {
        if observed.key.realm != self.scope.realm || observed.key.owner != self.scope.owner {
            return Err(PrivateOriginalError::Denied);
        }
        self.service_input_host_current()?;
        if observed.data.schema != SOURCE_SCHEMA {
            return Ok(PrivateOriginalCancellation::OperationsCancelled);
        }
        let current = self.store.get(&observed.key).await.map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        self.service_input_host_current()?;
        let current = Arc::new(current);
        if !self.decode_stored(&current)?.operation_cancelled {
            return Ok(PrivateOriginalCancellation::OperationsCancelled);
        }
        self.depart_cancelled_workflows(&[current]).await
    }
}
