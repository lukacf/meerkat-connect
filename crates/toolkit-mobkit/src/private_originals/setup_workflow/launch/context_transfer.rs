//! Completed inline disclosure to one explicitly selected private recipient.
//! The native Find fence owns the durable commit. Later recipient observation
//! grants no model input or waiter effect and exposes no raw payload getter.
use super::*;
mod delivery;
mod restore;
mod metadata;
#[cfg(test)]
mod restore_tests;
pub use delivery::WorkflowDeliveryObservation;
use crate::installed_host::acquisition::{InstalledOriginalInvocation, recovery::RecoveryControl};
use meerkat_authorization_contracts::constraints::AudienceRef;
use meerkat_authorization_contracts::work_association::InputAuthorityAssociation;
use meerkat_core::{ToolCallView, ToolDispatchContext};
use meerkat_toolkit::{
    authority::Ceiling,
    host_lifetime::control::HostLifetimeError,
    request::{FindAndInstallRequest, RequestContext},
    setup::{SetupSnapshot, SetupWorkBackend, SetupWorkBackendPin},
};
use meerkat_workgraph::{
    CreateWorkItemRequest, WorkAdmission, WorkAdmissionKey, WorkAdmissionOutcome,
    WorkGraphService, WorkGraphStoreKind,
    WorkItem, WorkNamespace, WorkStatus,
};
use std::collections::BTreeSet;

mod commit;
#[cfg(test)]
pub(crate) use commit::OwnedTransferCommit;

const PURPOSE: &str = "toolkit-workflow-inline-context-v1";

/// Exact host opt-in for one A invocation and one G/P recipient. Construction
/// requires the actual invocation supplied to original_binding. The host must
/// keep the supplied private namespace off every A/B model-facing graph surface.
/// This selection grants no native operation and never changes a native grant.
pub struct InstalledWorkflowContextTransfer {
    source: Weak<PrivateOriginals>,
    original: Weak<RetainedToolkitOriginal>,
    planning: Weak<InstalledWorkflowPlanning>,
    service: WorkGraphService,
    selected: TransferSelection,
    attempt: Mutex<Option<Arc<TransferAttempt>>>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferSelection {
    original: PrivateOriginalRef,
    association: InputAuthorityAssociation,
    correlation: Id,
    workflow: SetupWorkflowRef,
    planning_source: PrivateOriginalRef,
    parent: InputAuthorityAssociation,
    lead: MobMemberBinding,
    backend: SetupWorkBackendPin,
    recipient_realm: String,
    recipient_namespace: WorkNamespace,
    native_audience: AudienceRef,
    output_audiences: BTreeSet<Id>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferEnvelope {
    purpose: String,
    recipient: TransferSelection,
    membership: SetupWorkflowWaiter,
    input_digest: ContentDigest,
    find_call: String,
    find_scope: serde_json::Value,
    request: FindAndInstallRequest,
    deadline_ms: u64,
}

struct TransferAttempt {
    envelope: TransferEnvelope,
    request: CreateWorkItemRequest,
    admission: WorkAdmission,
    origin: TransferOrigin,
    recovery: Weak<RecoveryControl>,
    delivery: Mutex<Option<Arc<delivery::DeliverySlot>>>,
    advance: Mutex<Option<Arc<delivery::DeliveryRun>>>,
}

/// A store hit is not a joined physical task and cannot prove absence or retry.
enum TransferOrigin {
    Entered(commit::OwnedTransferCommit),
    ObservedCommitted,
}


/// The Find caller's historical commit observation. It does not acknowledge the
/// separate delivery intent or authorize a G input, installation or tool effect.
#[derive(Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum WorkflowTransferObservation {
    Committed { admission: WorkAdmission },
}

/// A protected recipient observation. Absence is only returned after this
/// owner's one entered attempt has joined, and never permits an automatic retry.
pub enum WorkflowContextObservation {
    Pending,
    Absent,
    Committed(InstalledWorkflowContext),
}

/// Opaque recipient-bound custody. No string accessor or serialization exposes
/// payload after the observation check. A later native delivery owner must
/// consume this custody and recheck G/P and recipient closure at admission.
pub struct InstalledWorkflowContext {
    transfer: Arc<InstalledWorkflowContextTransfer>,
    attempt: Arc<TransferAttempt>,
    workflow: Arc<HeldSetupWorkflow>,
}

impl InstalledWorkflowPlanning {
    /// Non-authority locator for the host's exclusive workflow recipient scope.
    /// The host supplies an actual service for it; this name grants no access.
    pub fn context_namespace(&self) -> Result<WorkNamespace, PrivateOriginalError> {
        let source = self.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let reference = source.workflow_store()?.workflow_ref(&self.terms)
            .map_err(|_| PrivateOriginalError::Conflict)?;
        PrivateOriginals::workflow_context_namespace(&reference)
    }
}

impl PrivateOriginals {
    pub(crate) fn workflow_context_namespace(workflow: &SetupWorkflowRef) -> Result<WorkNamespace, PrivateOriginalError> {
        let bytes = canonical_json(workflow).map_err(|_| PrivateOriginalError::Conflict)?;
        WorkNamespace::new(format!("toolkit-workflow-context/{}", digest(&bytes)))
            .map_err(|_| PrivateOriginalError::Conflict)
    }

    pub(crate) fn check_context_restore_host(&self, expected: &Arc<meerkat_toolkit::host_lifetime::NativeHostLifetime>)
        -> Result<(), PrivateOriginalError>
    {
        let actual = self.host_lifetime.get().and_then(Weak::upgrade).ok_or(PrivateOriginalError::Unavailable)?;
        if !Arc::ptr_eq(&actual, expected) { return Err(PrivateOriginalError::Denied); }
        self.service_input_host_current()
    }

    /// The trusted original_binding producer explicitly allows the exact
    /// invocation's canonical inline request to this fixed G/P recipient.
    /// This first profile requires equal actual A/G native audiences. The
    /// output audience set additionally narrows the setup proposal ceiling.
    /// The private service must be scoped by the host itself: this method does
    /// not rescope, replace or widen any supplied namespace grant.
    pub async fn prepare_workflow_context_transfer(
        self: &Arc<Self>,
        invocation: &InstalledOriginalInvocation<'_>,
        planning: Arc<InstalledWorkflowPlanning>,
        recipient: WorkGraphService,
        backend: &SetupWorkBackend,
        output_audiences: BTreeSet<Id>,
    ) -> Result<Arc<InstalledWorkflowContextTransfer>, PrivateOriginalError> {
        let original = self.acquisition_original(invocation.context()).await?;
        if &original.reference != invocation.original()
            || original.original.association() != invocation.association()
            || output_audiences.is_empty()
        { return Err(PrivateOriginalError::Denied); }
        planning.check_for_binding(self, &planning.submission.original)?;
        let route = self.route(&planning.submission.original.route)?;
        let workflow = self.workflow_store()?.workflow_ref(&planning.terms)
            .map_err(|_| PrivateOriginalError::Conflict)?;
        let selected = TransferSelection {
            original: original.reference.clone(), association: original.original.association().clone(),
            correlation: invocation.correlation().clone(), workflow,
            planning_source: planning.submission.original.clone(),
            parent: planning.parent.association().clone(), lead: planning.terms.lead.clone(),
            backend: backend.pin().clone(), recipient_realm: recipient.default_realm_id().into(),
            recipient_namespace: recipient.default_namespace().clone(),
            native_audience: route.grant_audience.clone(), output_audiences,
        };
        let candidate = Arc::new(InstalledWorkflowContextTransfer {
            source: Arc::downgrade(self), original: Arc::downgrade(&original.original),
            planning: Arc::downgrade(&planning), service: recipient, selected, attempt: Mutex::new(None),
        });
        candidate.check_selection(self, &original, invocation.correlation(), &planning)?;
        candidate.check_backend(backend)?;
        // Admission retains the first optional choice under its existing lock.
        // Equal later producer objects are discarded in favor of that actual
        // retained attempt owner; a changed choice conflicts there.
        Ok(candidate)
    }

    pub(crate) fn retained_workflow_context_transfer(
        &self, original: &Arc<RetainedToolkitOriginal>, correlation: &Id,
    ) -> Result<Option<Arc<InstalledWorkflowContextTransfer>>, PrivateOriginalError> {
        let held = self.retained.lock().map_err(|_| PrivateOriginalError::Unavailable)?
            .iter().find(|held| Arc::ptr_eq(&held.original, original)).cloned()
            .ok_or(PrivateOriginalError::Unavailable)?;
        let selected = held.workflow_selections.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
        Ok(selected.iter().find(|row| &row.correlation == correlation)
            .and_then(|row| row.context_transfer.as_ref()).map(|weak| weak.upgrade()
                .ok_or(PrivateOriginalError::Unavailable)).transpose()?)
    }

    pub(crate) fn workflow_context_transfers(&self)
        -> Result<Vec<Arc<InstalledWorkflowContextTransfer>>, PrivateOriginalError>
    {
        let held = self.retained.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
        let mut transfers = Vec::new();
        for original in held.iter() {
            let plans = original.workflow_plans.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            for planning in plans.iter() {
                let selected = planning.context_transfers.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
                for transfer in selected.iter() {
                    // Dormant choices do not delay recovery. A cold committed
                    // origin participates without inventing a physical join.
                    if transfer.attempt.lock().map_err(|_| PrivateOriginalError::Unavailable)?.is_some() {
                        transfers.push(transfer.clone());
                    }
                }
            }
        }
        Ok(transfers)
    }

    pub(crate) async fn join_workflow_context_transfers(&self, finished_only: bool) -> Result<(), PrivateOriginalError> {
        // The existing stop owner excludes registration before this census.
        let mut attempts = Vec::new();
        for transfer in self.workflow_context_transfers()? {
            if let Some(attempt) = transfer.attempt.lock().map_err(|_| PrivateOriginalError::Unavailable)?.clone() {
                attempts.push(attempt);
            }
        }
        for attempt in attempts {
            // An unsuccessful transfer can still be joined. It is not a
            // shutdown failure unless its native task owner failed to join.
            if !finished_only || attempt.finished() { let _ = attempt.join().await; }
            let advance = attempt.advance.lock().map_err(|_| PrivateOriginalError::Unavailable)?.clone();
            if let Some(advance) = advance {
                if !finished_only || advance.finished() { let _ = advance.join().await; }
            }
            let delivery = attempt.delivery.lock().map_err(|_| PrivateOriginalError::Unavailable)?.clone();
            if let Some(delivery) = delivery { delivery.join(finished_only).await?; }
        }
        Ok(())
    }
}

pub(super) fn same_transfer(
    prior: Option<&Arc<InstalledWorkflowContextTransfer>>,
    next: Option<&Arc<InstalledWorkflowContextTransfer>>,
) -> Result<bool, PrivateOriginalError> {
    Ok(match (prior, next) {
        (None, None) => true,
        (Some(a), Some(b)) => a.selected == b.selected
            && Weak::ptr_eq(&a.planning, &b.planning)
            && Arc::ptr_eq(a.service.store(), b.service.store()),
        _ => false,
    })
}

impl InstalledWorkflowContextTransfer {
    fn planning(&self) -> Result<Arc<InstalledWorkflowPlanning>, PrivateOriginalError> {
        self.planning.upgrade().ok_or(PrivateOriginalError::Unavailable)
    }

    fn canonical(self: &Arc<Self>) -> Result<Arc<Self>, PrivateOriginalError> {
        let planning = self.planning()?;
        let selected = planning.context_transfers.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
        let prior = selected.iter().find(|row| row.selected.original == self.selected.original
            && row.selected.correlation == self.selected.correlation)
            .ok_or(PrivateOriginalError::Unavailable)?;
        if !same_transfer(Some(prior), Some(self))? { return Err(PrivateOriginalError::Conflict); }
        Ok(prior.clone())
    }

    pub(crate) fn binding_digest(&self) -> Result<ContentDigest, PrivateOriginalError> {
        canonical_json(&(PURPOSE, &self.selected)).map(|bytes| ContentDigest::of_bytes(&bytes))
            .map_err(|_| PrivateOriginalError::Conflict)
    }

    pub(crate) fn check_selection(
        &self, source: &Arc<PrivateOriginals>,
        original: &super::super::super::acquisition::AcquisitionOriginal,
        correlation: &Id, planning: &Arc<InstalledWorkflowPlanning>,
    ) -> Result<(), PrivateOriginalError> {
        let actual = self.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let a = self.original.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        if !Arc::ptr_eq(&actual, source) || !Arc::ptr_eq(&a, &original.original)
            || !Weak::ptr_eq(&Arc::downgrade(planning), &self.planning) || &self.selected.correlation != correlation
            || self.selected.original != original.reference
            || &self.selected.association != original.original.association()
            || self.selected.planning_source != planning.submission.original
            || &self.selected.parent != planning.parent.association()
            || self.selected.lead != planning.terms.lead
            || self.selected.native_audience != original.original.association().candidate().target.audience
            || source.route(&self.selected.planning_source.route)?.grant_audience != self.selected.native_audience
        { return Err(PrivateOriginalError::Denied); }
        planning.check_for_binding(source, &self.selected.planning_source)?;
        source.owner.workflow_controller(&original.original).map_err(custody_error)?;
        Ok(())
    }

    fn check_backend(&self, backend: &SetupWorkBackend) -> Result<(), PrivateOriginalError> {
        let planning = self.planning()?;
        let grant = self.service.namespace_grant();
        if backend.pin() != &self.selected.backend || backend.pin() != &planning.terms.backend
            || !Arc::ptr_eq(backend.service().store(), self.service.store())
            || self.service.store().kind() != WorkGraphStoreKind::Sqlite
            || grant.realm_id != planning.terms.realm.to_string()
            || grant.realm_id != self.selected.recipient_realm
            || grant.namespace != self.selected.recipient_namespace.as_str()
            || self.service.default_namespace() != &planning.context_namespace()?
            || self.service.default_namespace() == backend.service().default_namespace()
        { return Err(PrivateOriginalError::Denied); }
        Ok(())
    }

    pub(crate) fn check_invocation(
        &self, source: &Arc<PrivateOriginals>,
        original: &super::super::super::acquisition::AcquisitionOriginal,
        correlation: &Id, planning: &Arc<InstalledWorkflowPlanning>,
        backend: &SetupWorkBackend, ceiling: &Ceiling,
    ) -> Result<(), PrivateOriginalError> {
        self.check_selection(source, original, correlation, planning)?;
        self.check_backend(backend)?;
        if self.selected.output_audiences.is_empty()
            || !self.selected.output_audiences.is_subset(&ceiling.output_audiences)
        { return Err(PrivateOriginalError::Denied); }
        Ok(())
    }

    pub(crate) async fn commit(
        self: &Arc<Self>, snapshot: &SetupSnapshot, membership: &SetupWorkflowWaiter,
        call: ToolCallView<'_>, context: &ToolDispatchContext,
        backend: &SetupWorkBackend, control: &Arc<RecoveryControl>,
    ) -> Result<WorkflowTransferObservation, PrivateOriginalError> {
        let source = self.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let original = source.acquisition_original(context).await?;
        let planning = self.planning()?;
        let request = snapshot.request();
        self.check_invocation(&source, &original, &request.host().correlation,
            &planning, backend, &request.constraints().ceiling)?;
        let parsed: FindAndInstallRequest = call.parse_args().map_err(|_| PrivateOriginalError::Denied)?;
        if call.name != crate::FIND_AND_INSTALL || &parsed != request.request()
            || request.request().user_context.iter().any(|item| matches!(item, RequestContext::Reference(_)))
            || request.evidence().association() != &self.selected.association
            || membership.workflow() != &self.selected.workflow
            || membership.acquisition() != snapshot.key()
            || membership.source() != &original.source_record.key
            || snapshot.state().terminal_revision != 0
        { return Err(PrivateOriginalError::Denied); }
        let canonical = source.workflow_store()?.load_setup_workflow(&self.selected.workflow)
            .await.map_err(|_| PrivateOriginalError::Unavailable)?;
        if canonical.terms() != &planning.terms || canonical.departed(membership)
            .map_err(|_| PrivateOriginalError::Conflict)?
        { return Err(PrivateOriginalError::Denied); }
        let envelope = TransferEnvelope {
            purpose: PURPOSE.into(), recipient: self.selected.clone(), membership: membership.clone(),
            input_digest: request.input_digest().clone(), find_call: call.id.into(),
            find_scope: serde_json::to_value(context.work_authorization()
                .ok_or(PrivateOriginalError::Denied)?.execution_scope())
                .map_err(|_| PrivateOriginalError::Conflict)?,
            request: parsed, deadline_ms: request.host().limits.deadline_ms,
        };
        let create = creation_request(&envelope)?;
        let key = admission_key(membership)?;
        let admission = self.service.admission_identity(key.clone(), create.clone())
            .map_err(|_| PrivateOriginalError::Conflict)?;
        // No await separates spawn from retention. The same stop lock excludes
        // a new attempt after the recovery worker's final drain begins.
        let attempt = control.enter_transfer(|| {
            let mut slot = self.attempt.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            if let Some(prior) = slot.as_ref() {
                return if prior.envelope == envelope && prior.admission == admission {
                    Ok(prior.clone())
                } else { Err(PrivateOriginalError::Conflict) };
            }
            let join = commit::OwnedTransferCommit::start(call, context, source.owner.clone(),
                self.service.clone(), key, create.clone(), envelope.deadline_ms)?;
            let held = Arc::new(TransferAttempt { envelope, request: create, admission,
                origin: TransferOrigin::Entered(join),
                recovery: Arc::downgrade(control), delivery: Mutex::new(None), advance: Mutex::new(None) });
            *slot = Some(held.clone());
            Ok(held)
        }).ok_or(PrivateOriginalError::Unavailable)??;
        Ok(WorkflowTransferObservation::Committed { admission: attempt.join().await? })
    }

    /// The coordinator and retained census pass the canonical transfer here.
    /// Retain the whole automatic step before its first async observation, so
    /// a bounded caller poll cannot restart a slow pre-dispatch store read.
    /// Metadata may finish after close. New entry still requires protected
    /// observation and the delivery slot's own retry decision.
    pub(crate) async fn advance_delivery(self: &Arc<Self>)
        -> Result<WorkflowDeliveryObservation, PrivateOriginalError>
    {
        let attempt = self.attempt.lock().map_err(|_| PrivateOriginalError::Unavailable)?.clone();
        let Some(attempt) = attempt else { return Ok(WorkflowDeliveryObservation::Pending); };
        // Reconstructed disclosures can only observe historical admission.
        // Their existing advance owner never enters the fresh delivery path.
        if !attempt.locally_entered() { return self.reconcile_delivery().await; }
        if !attempt.finished() { return Ok(WorkflowDeliveryObservation::Pending); }
        let control = attempt.recovery.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let transfer = self.clone();
        let run = delivery::DeliveryRun::register_advance(&control, &attempt.advance, move || async move {
                match transfer.reconcile_delivery().await? {
                    admitted @ WorkflowDeliveryObservation::Admitted { .. } => Ok(admitted),
                    WorkflowDeliveryObservation::Pending | WorkflowDeliveryObservation::NotApplied => {
                        match transfer.observe().await? {
                            WorkflowContextObservation::Committed(context) => context.deliver().await,
                            WorkflowContextObservation::Pending | WorkflowContextObservation::Absent =>
                                Ok(WorkflowDeliveryObservation::Pending),
                        }
                    }
                }
        })?;
        run.join().await
    }

    /// Observe this exact transfer under the current G/P recipient. An ended
    /// Find is never replayed, and a departed A is not treated as recall. The
    /// returned custody still requires G admission checks before future use.
    pub async fn observe(self: &Arc<Self>) -> Result<WorkflowContextObservation, PrivateOriginalError> {
        let source = self.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        // Recipient ownership survives A departure and equal producer aliases.
        let retained = self.canonical()?;
        retained.observe_retained(&source).await
    }

    async fn observe_retained(self: &Arc<Self>, source: &Arc<PrivateOriginals>)
        -> Result<WorkflowContextObservation, PrivateOriginalError>
    {
        let attempt = self.attempt.lock().map_err(|_| PrivateOriginalError::Unavailable)?.clone();
        let Some(attempt) = attempt else {
            return self.with_recipient(&source, |_| Ok(WorkflowContextObservation::Pending)).await;
        };
        // Cancellation of this await leaves the exact handle in its owner.
        // No read of A currentness is required after completed disclosure.
        let _ = attempt.join().await;
        self.with_recipient(&source, |_| Ok(())).await?;
        let result = self.service.observe_admission(attempt.admission.key.clone(), attempt.request.clone()).await;
        self.with_recipient(&source, |workflow| {
            // All data, including absence/conflict/backend errors, remains
            // private until this final recipient reservation. No A-current
            // helper or historical permission token authorizes this release.
            match result.map_err(|_| PrivateOriginalError::Unavailable)? {
                None if attempt.locally_entered() => Ok(WorkflowContextObservation::Absent),
                None => Ok(WorkflowContextObservation::Pending),
                Some(WorkAdmissionOutcome::Replayed(item)) => {
                    validate_item(&self.service, &attempt.admission, &attempt.request, &item)?;
                    Ok(WorkflowContextObservation::Committed(InstalledWorkflowContext {
                        transfer: self.clone(), attempt, workflow,
                    }))
                }
                Some(_) => Err(PrivateOriginalError::Conflict),
            }
        }).await
    }

    async fn with_recipient<T: Send>(&self, source: &Arc<PrivateOriginals>,
        disclose: impl FnOnce(Arc<HeldSetupWorkflow>) -> Result<T, PrivateOriginalError> + Send)
        -> Result<T, PrivateOriginalError>
    {
        let planning = self.planning()?;
        let actual = self.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        if !Arc::ptr_eq(source, &actual) || self.selected.planning_source != planning.submission.original
            || &self.selected.parent != planning.parent.association() || self.selected.lead != planning.terms.lead
            || self.selected.workflow != source.workflow_store()?.workflow_ref(&planning.terms)
                .map_err(|_| PrivateOriginalError::Conflict)?
            || self.selected.native_audience != source.route(&planning.submission.original.route)?.grant_audience
        { return Err(PrivateOriginalError::Denied); }
        planning.with_context_recipient(source, disclose).await
    }
}

impl InstalledWorkflowPlanning {
    async fn with_context_recipient<T: Send>(&self, source: &Arc<PrivateOriginals>,
        disclose: impl FnOnce(Arc<HeldSetupWorkflow>) -> Result<T, PrivateOriginalError> + Send)
        -> Result<T, PrivateOriginalError>
    {
        let actual = self.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let planning = self;
        let reference = source.workflow_store()?.workflow_ref(&self.terms).map_err(|_| PrivateOriginalError::Conflict)?;
        let audience = source.route(&self.submission.original.route)?.grant_audience.clone();
        if !Arc::ptr_eq(source, &actual) { return Err(PrivateOriginalError::Denied); }
        let snapshot = source.workflow_store()?.load_setup_workflow(&reference)
            .await.map_err(|_| PrivateOriginalError::Unavailable)?;
        // A may be departed. At least one recipient workflow interest must
        // remain; final closure fences consumption of every transferred item.
        if snapshot.terms() != &planning.terms || snapshot.active_waiters() == 0 {
            return Err(PrivateOriginalError::Denied);
        }
        let held = source.retained.lock().map_err(|_| PrivateOriginalError::Unavailable)?
            .iter().find(|held| held.reference == self.submission.original).cloned()
            .ok_or(PrivateOriginalError::Unavailable)?;
        let workflow = held.setup_workflow.get().cloned().ok_or(PrivateOriginalError::Unavailable)?;
        let lifetime = source.host_lifetime.get().and_then(Weak::upgrade)
            .ok_or(PrivateOriginalError::Unavailable)?;
        // Existing setup lock order is host phase/entry before the native
        // publication reservation. No callback reenters the host owner.
        lifetime.with_current_setup(|| {
            source.owner.grants().try_with_owner_changes_excluded(|| {
                planning.check_for_binding(source, &self.submission.original)?;
                workflow.current_source()?;
                if workflow.reference != reference || workflow.member != self.terms.lead
                    || !Arc::ptr_eq(&workflow.planning, &held.original)
                    || held.original.association().candidate().target.audience != audience
                    || source.owner.dedicated_workflow_session(&reference, &self.terms.lead,
                        &self.submission.original.original).map_err(custody_error)?
                        .as_ref() != Some(&workflow.session)
                { return Err(PrivateOriginalError::Denied); }
                for original in [&planning.parent, &held.original] {
                    let claims = original.association().candidate();
                    source.owner.workflow_controller(original).map_err(custody_error)?;
                    for lineage in claims.authority_basis.grant_lineages() {
                        source.owner.grants().resolve_lineage(lineage, &claims.logical_executor,
                            claims.represented_subject.as_ref()).map_err(|_| PrivateOriginalError::Denied)?
                            .check_current().map_err(|_| PrivateOriginalError::Unavailable)?;
                    }
                    source.owner.grants().resolve_controller_lineage(&claims.controller_grant_lineage,
                        &claims.logical_executor, claims.represented_subject.as_ref())
                        .map_err(|_| PrivateOriginalError::Denied)?
                        .check_current().map_err(|_| PrivateOriginalError::Unavailable)?;
                }
                let now = source.owner.clock().now().map_err(|_| PrivateOriginalError::Unavailable)?;
                let interests = planning.interests.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
                if !interests.iter().any(|interest| !interest.closed
                    && now.unix_ms < interest.membership.deadline_ms()
                    && interest.membership.workflow() == &reference) {
                    return Err(PrivateOriginalError::Denied);
                }
                disclose(workflow)
            }).map_err(|_| HostLifetimeError::Unavailable)
        }).map_err(|error| match error {
            HostLifetimeError::Unavailable => PrivateOriginalError::Unavailable,
            _ => PrivateOriginalError::Denied,
        })?
    }
}

impl TransferAttempt {
    fn locally_entered(&self) -> bool { matches!(self.origin, TransferOrigin::Entered(_)) }
    fn finished(&self) -> bool {
        match &self.origin { TransferOrigin::Entered(join) => join.finished(), TransferOrigin::ObservedCommitted => true }
    }
    async fn join(&self) -> Result<WorkAdmission, PrivateOriginalError> {
        match &self.origin {
            TransferOrigin::Entered(join) => join.join().await,
            // This returns only the already verified immutable admission. It
            // does not record or impersonate a physical task settlement.
            TransferOrigin::ObservedCommitted => Ok(self.admission.clone()),
        }
    }
}

fn admission_key(membership: &SetupWorkflowWaiter) -> Result<WorkAdmissionKey, PrivateOriginalError> {
    WorkAdmissionKey::new(format!("toolkit-context-{}", digest(&canonical_json(membership.acquisition())
        .map_err(|_| PrivateOriginalError::Conflict)?))).map_err(|_| PrivateOriginalError::Conflict)
}

fn creation_request(envelope: &TransferEnvelope) -> Result<CreateWorkItemRequest, PrivateOriginalError> {
    Ok(CreateWorkItemRequest {
        realm_id: Some(envelope.recipient.recipient_realm.clone()),
        namespace: Some(envelope.recipient.recipient_namespace.clone()),
        title: "Toolkit workflow context".into(),
        description: Some(String::from_utf8(canonical_json(envelope)
            .map_err(|_| PrivateOriginalError::Conflict)?).map_err(|_| PrivateOriginalError::Conflict)?),
        status: Some(WorkStatus::Open), ..Default::default()
    })
}
fn validate_item(service: &WorkGraphService, admission: &WorkAdmission,
    request: &CreateWorkItemRequest, item: &WorkItem) -> Result<(), PrivateOriginalError>
{
    validate_item_identity(service, admission, request, item)?;
    let envelope: TransferEnvelope = serde_json::from_str(item.description.as_deref()
        .ok_or(PrivateOriginalError::Conflict)?).map_err(|_| PrivateOriginalError::Conflict)?;
    if envelope.purpose != PURPOSE || canonical_json(&creation_request(&envelope)?)
        .map_err(|_| PrivateOriginalError::Conflict)? != canonical_json(request)
        .map_err(|_| PrivateOriginalError::Conflict)?
    { return Err(PrivateOriginalError::Conflict); }
    Ok(())
}

fn validate_item_identity(service: &WorkGraphService, admission: &WorkAdmission,
    request: &CreateWorkItemRequest, item: &WorkItem) -> Result<(), PrivateOriginalError>
{
    let rebuilt = CreateWorkItemRequest {
        realm_id: Some(item.realm_id.clone()), namespace: Some(item.namespace.clone()),
        title: item.title.clone(), description: item.description.clone(), priority: item.priority,
        completion_policy: item.completion_policy.clone(), failed_child_join_policy: item.failed_child_join_policy,
        cancelled_child_join_policy: item.cancelled_child_join_policy,
        labels: item.labels.clone(), due_at: item.due_at, not_before: item.not_before,
        snoozed_until: item.snoozed_until, external_refs: item.external_refs.clone(),
        evidence_refs: item.evidence_refs.clone(), status: Some(item.status),
    };
    if service.admission_identity(admission.key.clone(), rebuilt)
        .map_err(|_| PrivateOriginalError::Conflict)? != *admission
        || service.admission_identity(admission.key.clone(), request.clone())
            .map_err(|_| PrivateOriginalError::Conflict)? != *admission
    { return Err(PrivateOriginalError::Conflict); }
    Ok(())
}
