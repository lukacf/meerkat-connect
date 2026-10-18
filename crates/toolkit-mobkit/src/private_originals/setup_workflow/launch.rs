//! Host-selected first G input through the existing Original binder and outbox.
//! The launch receipt never acknowledges any waiter's context-delivery intent.
use super::*;

mod context_transfer;
#[cfg(test)]
pub(crate) use context_transfer::OwnedTransferCommit;
pub use context_transfer::{InstalledWorkflowContextTransfer, InstalledWorkflowContext, WorkflowContextObservation, WorkflowDeliveryObservation};
pub(crate) use context_transfer::WorkflowTransferObservation;
mod close;
mod restore;
mod recovery;
pub(crate) use recovery::WorkflowInterestRecovery;
pub(crate) use close::{WorkflowCloseObservation, WorkflowTerminalRecovery};
use crate::private_originals::governed_submit::{OriginalBinder, evidence};
use meerkat_authorization_contracts::{constraints::DelegationDepth, grant::GrantLineageRef};
use meerkat_mobkit::identity_first::{
    BoundGovernedInput, GovernedBindContext, GovernedEntryFence, GovernedEntryOutcome,
    GovernedEntryPermit, GovernedEntryRefusal, GovernedInputBinder, GovernedInputError,
    GovernedSettlement, IdentityRuntimeError, TurnTracking,
};
use meerkat_runtime::{Input, PromptInput};
use meerkat_toolkit::setup::{SetupWorkContext, SetupWorkflowTerms};
use toolkit_store::{
    EffectClaimOutcome, EffectLease, EffectOutcome, EffectStatus, Reconciliation, StoreError,
};

/// The one launch owner's observation, never waiter-context delivery. Only an
/// exact pre-admission binder refusal or native settled refusal can produce
/// the definitive NotAdmitted case.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WorkflowLaunchObservation {
    Native {
        observation: PrivateOriginalSubmission,
    },
    NotAdmitted,
}

/// An actual host selection under PrivateOriginals, with no wire constructor.
/// Its independently authenticated parent and G task leaf are rechecked by
/// their existing owners. Workflow terms and grant references alone cannot
/// construct this handle or substitute for native admission.
pub struct InstalledWorkflowPlanning {
    source: Weak<PrivateOriginals>,
    parent: Arc<RetainedToolkitOriginal>,
    submission: PrivateOriginalSubmit,
    terms: SetupWorkflowTerms,
    lineage: Vec<GrantLineageRef>,
    interests: Mutex<Vec<LaunchInterest>>,
    // Canonical completed-context ownership survives donor departure.
    context_transfers: Mutex<Vec<Arc<InstalledWorkflowContextTransfer>>>,
}

struct LaunchInterest {
    membership: SetupWorkflowWaiter,
    // A closed membership may arrive before its local source interest.
    original: Option<Arc<RetainedToolkitOriginal>>,
    closed: bool,
    entries: Vec<Arc<crate::original_ingress::shared_entry::SharedEntry>>,
}

pub(crate) struct InvocationPlanning {
    correlation: Id,
    selection: Option<Arc<InstalledWorkflowPlanning>>,
    // Invocation selection is an alias; the recipient planning owner retains custody.
    context_transfer: Option<Weak<InstalledWorkflowContextTransfer>>,
}

/// Canonical launch data staged before native admission. No durable store read
/// is performed by the synchronous accepted callback.
pub(in crate::private_originals) struct PreparedWorkflowLaunch {
    selection: Arc<InstalledWorkflowPlanning>,
    reference: SetupWorkflowRef,
}

impl PrivateOriginals {
    /// Called by the host's original_binding producer. The source event must
    /// already be retained by this same authenticated application. The actual
    /// G task leaf must be independently issued to G, not borrowed from A.
    /// Its complete bounds are the workflow's frozen operation envelope.
    pub async fn prepare_workflow_planning(
        self: &Arc<Self>,
        parent: &PrivateOriginalRef,
        submission: PrivateOriginalSubmit,
        terms: SetupWorkflowTerms,
        lineage: Vec<GrantLineageRef>,
    ) -> Result<Arc<InstalledWorkflowPlanning>, PrivateOriginalError> {
        self.workflow_store()?
            .workflow_ref(&terms)
            .map_err(|_| PrivateOriginalError::Conflict)?;
        let parent = self
            .retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .iter()
            .find(|held| &held.reference == parent)
            .cloned()
            .ok_or(PrivateOriginalError::Unavailable)?;
        self.owner
            .workflow_controller(&parent.original)
            .map_err(custody_error)?;
        let event = self.event(&submission.original).await?;
        let route = self.route(&submission.original.route)?;
        let p = parent.original.association().candidate();
        if terms.planning_source != self.key(&submission.original)?
            || terms.requester != p.requester
            || terms.realm != p.ingress_namespace.realm
            || route.requester != terms.requester
            || route.realm != terms.realm
            || route.source_authority != p.original_work.authority
            || event.contributors.as_slice() != [p.original_work.work.clone()]
            || digest(submission.content.as_bytes()) != event.content_sha256
            || submission.original == parent.reference
            || lineage.len() < 2
        {
            return Err(PrivateOriginalError::Denied);
        }
        let lifetime = self
            .host_lifetime
            .get()
            .and_then(Weak::upgrade)
            .ok_or(PrivateOriginalError::Unavailable)?;
        lifetime
            .validate_current_selection()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let selected = lifetime.selected_policy();
        let native = selected
            .native_host
            .as_ref()
            .ok_or(PrivateOriginalError::Unavailable)?;
        let compiled = native
            .routes
            .iter()
            .find(|candidate| candidate.id == submission.original.route)
            .ok_or(PrivateOriginalError::Denied)?;
        let (member, requester, actor) = compiled
            .source_binding(selected)
            .map_err(|_| PrivateOriginalError::Denied)?;
        if member != &terms.lead
            || requester != &route.requester
            || actor != &route.ingress_actor
            || route.grant_target.as_str() != terms.lead.member
        {
            return Err(PrivateOriginalError::Denied);
        }
        let record = self
            .store
            .get(&self.key(&submission.original)?)
            .await
            .map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        let record = self.decode_record(&record, &submission.original)?;
        if record.setup_request.is_some()
            || record.configured_setup.is_some()
            || record.approved_task.is_some()
            || record.operation_cancelled
        {
            return Err(PrivateOriginalError::Denied);
        }
        let candidate = Arc::new(InstalledWorkflowPlanning {
            source: Arc::downgrade(self),
            parent: parent.original.clone(),
            submission,
            terms,
            lineage,
            interests: Mutex::new(Vec::new()),
            context_transfers: Mutex::new(Vec::new()),
        });
        candidate.check_for_binding(self, &candidate.submission.original)?;
        // This actual host planning choice opts G into exact input evidence.
        // A legacy already-bound G remains usable without retrofitting a body.
        self.select_workflow_lead_evidence(&candidate.submission.original, &parent.reference).await?;
        // Intern this process custody on the actual authenticated P owner.
        // Equal terms cannot construct permission, and repeated host lookups
        // must select the same launch-interest reservations for A and B.
        let mut plans = parent
            .workflow_plans
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        if let Some(prior) = plans
            .iter()
            .find(|plan| plan.submission.original == candidate.submission.original)
        {
            return if same_optional(Some(prior), Some(&candidate)) {
                Ok(prior.clone())
            } else {
                Err(PrivateOriginalError::Conflict)
            };
        }
        if plans.len() >= 128 {
            return Err(PrivateOriginalError::Unavailable);
        }
        plans.push(candidate.clone());
        Ok(candidate)
    }

    /// Retain the exact optional producer result on the existing live A owner.
    /// Re-entry through admission cannot replace Some, erase it, or infer it
    /// from portable terms. The first None is retained too: concurrent first
    /// admissions may both have observed absent durable invocation terms.
    pub(crate) fn retain_workflow_selection(
        self: &Arc<Self>,
        original: &super::super::acquisition::AcquisitionOriginal,
        correlation: &Id,
        selection: Option<&Arc<InstalledWorkflowPlanning>>,
        work: Option<&SetupWorkContext>,
    ) -> Result<(), PrivateOriginalError> {
        self.retain_workflow_binding(original, correlation, selection, None, work)
    }

    pub(crate) fn retain_workflow_binding(
        self: &Arc<Self>,
        original: &super::super::acquisition::AcquisitionOriginal,
        correlation: &Id,
        selection: Option<&Arc<InstalledWorkflowPlanning>>,
        context_transfer: Option<&Arc<InstalledWorkflowContextTransfer>>,
        work: Option<&SetupWorkContext>,
    ) -> Result<(), PrivateOriginalError> {
        if let Some(transfer) = context_transfer {
            transfer.check_selection(self, original, correlation,
                selection.ok_or(PrivateOriginalError::Denied)?)?;
        }
        if let Some(selection) = selection {
            selection.check_for_binding(self, &selection.submission.original)?;
            let work = work.ok_or(PrivateOriginalError::Denied)?;
            let a = original.original.association().candidate();
            if selection.terms.requester != a.requester
                || selection.terms.realm != a.ingress_namespace.realm
                || work.backend() != &selection.terms.backend
                || work.parent() != &selection.terms.parent
                || Arc::ptr_eq(&selection.parent, &original.original)
            {
                return Err(PrivateOriginalError::Denied);
            }
        }
        let held = self
            .retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .iter()
            .find(|held| Arc::ptr_eq(&held.original, &original.original))
            .cloned()
            .ok_or(PrivateOriginalError::Unavailable)?;
        let mut selections = held
            .workflow_selections
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        if let Some(prior) = selections
            .iter()
            .find(|item| &item.correlation == correlation)
        {
            return if same_optional(prior.selection.as_ref(), selection)
                && context_transfer::same_transfer(
                    prior.context_transfer.as_ref().map(|weak| weak.upgrade()
                        .ok_or(PrivateOriginalError::Unavailable)).transpose()?.as_ref(), context_transfer)? {
                Ok(())
            } else {
                Err(PrivateOriginalError::Conflict)
            };
        }
        if selections.len() >= 128 {
            return Err(PrivateOriginalError::Unavailable);
        }
        // All donor-selection failures precede canonical recipient retention.
        let context_transfer = match context_transfer {
            Some(candidate) => Some(Arc::downgrade(&selection.ok_or(PrivateOriginalError::Denied)?
                .retain_context_transfer(candidate.clone())?)),
            None => None,
        };
        selections.push(InvocationPlanning {
            correlation: correlation.clone(),
            selection: selection.cloned(),
            context_transfer,
        });
        Ok(())
    }

    pub(crate) fn retained_workflow_selection(
        &self,
        original: &Arc<RetainedToolkitOriginal>,
        correlation: &Id,
    ) -> Result<Option<Arc<InstalledWorkflowPlanning>>, PrivateOriginalError> {
        let held = self
            .retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .iter()
            .find(|held| Arc::ptr_eq(&held.original, original))
            .cloned()
            .ok_or(PrivateOriginalError::Unavailable)?;
        let selections = held
            .workflow_selections
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        // Custom pre-default SetupToolHost owners never selected this optional
        // binding. They remain singleton; a recorded Some can never disappear.
        Ok(selections
            .iter()
            .find(|item| &item.correlation == correlation)
            .and_then(|item| item.selection.clone()))
    }
}

impl InstalledWorkflowPlanning {
    pub(in crate::private_originals) fn lineage(&self) -> &[GrantLineageRef] {
        &self.lineage
    }
    pub(crate) fn terms(&self) -> &SetupWorkflowTerms {
        &self.terms
    }
    /// Correlation in the existing immutable environment revision, not a
    /// transport for the live source handle or a grant to use it.
    pub(crate) fn binding_digest(&self) -> Result<ContentDigest, PrivateOriginalError> {
        canonical_json(&(
            "installed-workflow-selection-v1",
            &self.terms,
            &self.submission.original,
            &self.lineage,
        ))
        .map(|bytes| ContentDigest::of_bytes(&bytes))
        .map_err(|_| PrivateOriginalError::Conflict)
    }

    pub(in crate::private_originals) fn check_for_binding(
        &self,
        source: &Arc<PrivateOriginals>,
        original: &PrivateOriginalRef,
    ) -> Result<(), PrivateOriginalError> {
        let actual = self
            .source
            .upgrade()
            .ok_or(PrivateOriginalError::Unavailable)?;
        if !Arc::ptr_eq(source, &actual) || original != &self.submission.original {
            return Err(PrivateOriginalError::Denied);
        }
        source
            .owner
            .workflow_controller(&self.parent)
            .map_err(custody_error)?;
        let now = source
            .owner
            .clock()
            .now()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .unix_ms;
        if now >= self.terms.deadline_ms {
            return Err(PrivateOriginalError::Denied);
        }
        let route = source.route(&original.route)?;
        let grant = source
            .owner
            .grants()
            .resolve_lineage(
                &self.lineage,
                &route.logical_executor,
                route.represented_subject.as_ref(),
            )
            .map_err(|_| PrivateOriginalError::Denied)?;
        if grant.restrictions().delegation_depth != DelegationDepth::remaining(0)
            || grant.expires_at_ms() < self.terms.deadline_ms
            || ContentDigest::of_bytes(
                &canonical_json(grant.restrictions())
                    .map_err(|_| PrivateOriginalError::Conflict)?,
            ) != self.terms.envelope_digest
        {
            return Err(PrivateOriginalError::Denied);
        }
        grant
            .check_current()
            .map_err(|_| PrivateOriginalError::Unavailable)
    }

    /// The installed coordinator supplies its actual conditional SQLite
    /// adapter, which must be the same Arc retained by this source owner.
    /// Storage predicates fence a queued worker after caller loss; the source
    /// writer also orders the live currentness check against cancellation.
    pub(crate) async fn join_waiter_conditionally(
        &self,
        selected_store: &Arc<toolkit_store::SqliteStore>,
        membership: &SetupWorkflowWaiter,
        original: &super::super::acquisition::AcquisitionOriginal,
        access: SetupAccess<'_>,
        backend: &meerkat_toolkit::setup::SetupWorkBackend,
    ) -> Result<Result<meerkat_toolkit::setup::SetupWorkflowJoin, meerkat_toolkit::setup::SetupError>, PrivateOriginalError> {
        let source = self.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        self.check_for_binding(&source, &self.submission.original)?;
        let erased: Arc<dyn ToolkitStore> = selected_store.clone();
        if !Arc::ptr_eq(&source.store, &erased) || membership.source() != &original.source_record.key {
            return Err(PrivateOriginalError::Conflict);
        }
        let scope = SetupScope::new(
            Id::new(source.scope.realm.clone()).map_err(|_| PrivateOriginalError::Conflict)?,
            Id::new(source.scope.owner.clone()).map_err(|_| PrivateOriginalError::Conflict)?,
        );
        let store = SetupStore::new_conditional(selected_store.as_ref(), scope)
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        source.owner.retain_followup_source(original.original.association(), || async {
            // This is the actual retained source row, not a portable workflow
            // ref. An intervening durable source change makes the commit fail.
            let condition = toolkit_store::RecordCondition {
                key: original.source_record.key.clone(),
                revision: original.source_record.revision,
                content_digest: original.source_record.content_digest.clone(),
                claim: None, dispatch_claim: None,
            };
            Ok(store.join_setup_workflow_conditionally(
                &self.terms, membership, access, backend, condition,
            ).await)
        }).await.map_err(custody_error)
    }

    /// Validate the actual planning selection after the canonical source read,
    /// under the existing original writer. The shared persistence body still
    /// checks source facts, replay equality, cancellation and the source CAS.
    pub(in crate::private_originals) fn check_persistence_binding(
        &self,
        source: &PrivateOriginals,
        reference: &PrivateOriginalRef,
        record: &SourceRecord,
        association: &meerkat_authorization_contracts::work_association::InputAuthorityAssociation,
    ) -> Result<(), OriginalWriterError> {
        let actual = self.source.upgrade().ok_or(OriginalWriterError::Unavailable)?;
        if !std::ptr::eq(source, actual.as_ref()) {
            return Err(OriginalWriterError::WrongOwner);
        }
        self.check_for_binding(&actual, reference).map_err(|error| match error {
            PrivateOriginalError::Unavailable => OriginalWriterError::Unavailable,
            PrivateOriginalError::Conflict => OriginalWriterError::Conflict,
            PrivateOriginalError::Denied => OriginalWriterError::OperationDenied,
        })?;
        let claims = association.candidate();
        if record.setup_request.is_some()
            || record.configured_setup.is_some()
            || record.approved_task.is_some()
            || record.service_admission.is_some()
            || source.key(reference).map_err(|_| OriginalWriterError::WrongOwner)? != self.terms.planning_source
            || claims.requester != self.terms.requester
            || claims.ingress_namespace.realm != self.terms.realm
            || claims.contributing_work.as_slice() != [self.parent.association().candidate().original_work.clone()]
            || !matches!(&claims.authority_basis,
                meerkat_authorization_contracts::work_association::WorkAuthorityBasis::GrantLineage { lineage }
                    if lineage == &self.lineage)
        {
            return Err(OriginalWriterError::Conflict);
        }
        Ok(())
    }

    /// Canonical join is complete. Retain only actual A launch interest here.
    /// No pending native reservation exists until the final synchronous entry
    /// fence. P/G still supply the native input's independent authority.
    pub(crate) async fn retain_launch_interest(
        self: &Arc<Self>,
        snapshot: &SetupWorkflowSnapshot,
        membership: &SetupWorkflowWaiter,
        original: &super::super::acquisition::AcquisitionOriginal,
    ) -> Result<(), PrivateOriginalError> {
        let source = self
            .source
            .upgrade()
            .ok_or(PrivateOriginalError::Unavailable)?;
        self.check_for_binding(&source, &self.submission.original)?;
        if snapshot.terms() != &self.terms
            || membership.workflow() != snapshot.reference()
            || membership.source() != &original.source_record.key
            || snapshot
                .departed(membership)
                .map_err(|_| PrivateOriginalError::Conflict)?
            || Arc::ptr_eq(&self.parent, &original.original)
        {
            return Err(PrivateOriginalError::Denied);
        }
        source.owner.retain_followup_source(original.original.association(), || async {
        let current = source.workflow_store().map_err(|_| OriginalWriterError::Unavailable)?
            .load_setup_workflow(membership.workflow()).await.map_err(|_| OriginalWriterError::Unavailable)?;
        if current.terms() != &self.terms || current.departed(membership).map_err(|_| OriginalWriterError::Conflict)? {
            return Err(OriginalWriterError::OperationDenied);
        }
        source
            .owner
            .workflow_controller(&original.original)
            ?;
        {
            let mut interests = self
                .interests
                .lock()
                .map_err(|_| crate::original_ingress::OriginalWriterError::Unavailable)?;
            if let Some(prior) = interests
                .iter()
                .find(|interest| interest.membership.acquisition() == membership.acquisition())
            {
                return if prior.membership == *membership
                    && prior.original.as_ref().is_some_and(|held| Arc::ptr_eq(held, &original.original))
                    && !prior.closed
                {
                    Ok(())
                } else {
                    Err(crate::original_ingress::OriginalWriterError::Conflict)
                };
            }
            if interests.len() >= usize::from(self.terms.max_waiters) {
                return Err(crate::original_ingress::OriginalWriterError::Unavailable);
            }
            interests.push(LaunchInterest {
                membership: membership.clone(),
                original: Some(original.original.clone()),
                closed: false,
                entries: Vec::new(),
            });
            Ok(())
        }
        }).await.map_err(custody_error)
    }

    /// The actual waiter owner closes the same final-entry reservation before
    /// awaiting durable departure. A failed write leaves it closed; replay
    /// cannot reopen it. Accepted/uncertain native work remains owned until its
    /// actual admission observation, not inferred from this store transition.
    pub(crate) async fn depart_waiter(
        &self,
        membership: &SetupWorkflowWaiter,
    ) -> Result<SetupWorkflowSnapshot, PrivateOriginalError> {
        let source = self
            .source
            .upgrade()
            .ok_or(PrivateOriginalError::Unavailable)?;
        if source.workflow_store()?.workflow_ref(&self.terms)
            .map_err(|_| PrivateOriginalError::Conflict)? != *membership.workflow() {
            return Err(PrivateOriginalError::Denied);
        }
        let _writer = source.owner.source_writer().await;
        let prior_closed = {
            let interests = self.interests.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            match interests.iter().find(|interest| interest.membership.acquisition() == membership.acquisition()) {
                Some(interest) if interest.membership == *membership => Some(interest.closed),
                Some(_) => return Err(PrivateOriginalError::Conflict),
                None => None,
            }
        };
        if prior_closed.is_none() {
            // A lost join reply may have no local interest. Validate the exact
            // canonical row before this portable value can consume a slot.
            // The source writer prevents restoration from passing this read.
            let current = source.workflow_store()?.load_setup_workflow(membership.workflow())
                .await.map_err(|_| PrivateOriginalError::Unavailable)?;
            if current.terms() != &self.terms { return Err(PrivateOriginalError::Conflict); }
            current.departed(membership).map_err(|_| PrivateOriginalError::Conflict)?;
            if self.interests.lock().map_err(|_| PrivateOriginalError::Unavailable)?.len()
                >= usize::from(self.terms.max_waiters) { return Err(PrivateOriginalError::Unavailable); }
        }
        {
            let publication = source.owner.publication();
            // Only first closure changes source policy. Exact closed replay
            // retries entry closure and the canonical write without publishing.
            let _publication = if prior_closed == Some(true) { None } else {
                Some(publication.begin_owner_change().map_err(|_| PrivateOriginalError::Unavailable)?)
            };
            let mut interests = self.interests.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            if let Some(interest) = interests.iter_mut().find(|interest| interest.membership == *membership) {
                // An actual held interest closes before the first store await.
                interest.closed = true;
                for entry in &interest.entries { entry.close().map_err(custody_error)?; }
            } else {
                // Exact membership was validated above under this writer.
                // A failed durable departure leaves its tombstone closed.
                interests.push(LaunchInterest { membership: membership.clone(), original: None,
                    closed: true, entries: Vec::new() });
            }
        }
        // The closed entry is now published. Keep only the async source
        // writer across storage: native readers see closure, and restoration
        // cannot pass until canonical departure settles or the caller drops.
        source
            .workflow_store()?
            .depart_setup_workflow(membership)
            .await
            .map_err(|_| PrivateOriginalError::Unavailable)
    }

    fn settle_launch_interest(&self) -> Result<(), PrivateOriginalError> {
        let interests = self
            .interests
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        for interest in interests.iter() {
            for entry in &interest.entries {
                entry.settle().map_err(custody_error)?;
            }
        }
        Ok(())
    }

    /// Claim exactly the existing launch intent. An expired/lost claim is
    /// observed only: it never causes a second G input to be invented.
    pub(crate) async fn launch(
        self: &Arc<Self>,
        snapshot: &SetupWorkflowSnapshot,
    ) -> Result<WorkflowLaunchObservation, PrivateOriginalError> {
        let source = self
            .source
            .upgrade()
            .ok_or(PrivateOriginalError::Unavailable)?;
        self.check_for_binding(&source, &self.submission.original)?;
        if snapshot.terms() != &self.terms || snapshot.active_waiters() == 0 {
            return Err(PrivateOriginalError::Denied);
        }
        let key = snapshot.reference().launch_effect();
        let effect = source
            .store
            .get_effect(&key)
            .await
            .map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        if effect.attempt > 0 || effect.status != EffectStatus::Pending {
            return self.observe_launch(snapshot).await;
        }
        let claimed = match source
            .store
            .claim_effect(
                &key,
                snapshot.revision(),
                "installed-workflow-launch",
                60_000,
            )
            .await
        {
            Ok(claimed) => claimed,
            Err(StoreError::Claimed | StoreError::Conflict | StoreError::EffectState) => {
                return self.observe_launch(snapshot).await;
            }
            Err(error) => return Err(store_error(error)),
        };
        let EffectClaimOutcome::Claimed(claimed) = claimed else {
            return self.observe_launch(snapshot).await;
        };
        let lease = claimed.lease.ok_or(PrivateOriginalError::Unavailable)?;
        let prepared = Arc::new(PreparedWorkflowLaunch {
            selection: self.clone(),
            reference: snapshot.reference().clone(),
        });
        let remaining = self
            .terms
            .deadline_ms
            .checked_sub(
                source
                    .owner
                    .clock()
                    .now()
                    .map_err(|_| PrivateOriginalError::Unavailable)?
                    .unix_ms,
            )
            .ok_or(PrivateOriginalError::Denied)?;
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(remaining),
            prepared.submit(&source),
        )
        .await
        .unwrap_or(Err(PrivateOriginalError::Unavailable));
        // Meta retains its governed operation and binder/settlement after the
        // foreground receiver is dropped. Timeout is not proof of nonentry.
        let observation = result.unwrap_or(WorkflowLaunchObservation::Native {
            observation: PrivateOriginalSubmission::NativeOutcomeUnavailable,
        });
        self.record_launch_observation(&source, &lease, &observation)
            .await?;
        Ok(observation)
    }

    async fn record_launch_observation(
        &self,
        source: &PrivateOriginals,
        lease: &EffectLease,
        observation: &WorkflowLaunchObservation,
    ) -> Result<(), PrivateOriginalError> {
        let receipt = RecordData {
            schema: "toolkit.setup-workflow-launch".into(),
            version: 1,
            body: serde_json::to_value(&observation).map_err(|_| PrivateOriginalError::Conflict)?,
        };
        let outcome = match observation {
            WorkflowLaunchObservation::Native {
                observation:
                    PrivateOriginalSubmission::Admitted {
                        source_settlement: PrivateSourceSettlement::FreshAcceptancePromoted,
                        ..
                    },
            } => EffectOutcome::Succeeded { receipt },
            WorkflowLaunchObservation::NotAdmitted => EffectOutcome::Failed { evidence: receipt },
            _ => EffectOutcome::Uncertain { evidence: receipt },
        };
        source
            .store
            .acknowledge_effect(lease, outcome)
            .await
            .map_err(store_error)?;
        Ok(())
    }

    async fn observe_launch(
        &self,
        snapshot: &SetupWorkflowSnapshot,
    ) -> Result<WorkflowLaunchObservation, PrivateOriginalError> {
        let source = self
            .source
            .upgrade()
            .ok_or(PrivateOriginalError::Unavailable)?;
        self.check_for_binding(&source, &self.submission.original)?;
        let key = snapshot.reference().launch_effect();
        let effect = source
            .store
            .get_effect(&key)
            .await
            .map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        if effect.status == EffectStatus::Failed {
            // A definitive recorded decision for this exact launch is not
            // undone by absence of a native input row. It never permits replay.
            let Some(EffectOutcome::Failed { evidence }) = &effect.outcome else {
                return Err(PrivateOriginalError::Conflict);
            };
            if evidence.schema != "toolkit.setup-workflow-launch" || evidence.version != 1 {
                return Err(PrivateOriginalError::Conflict);
            }
            let observed: WorkflowLaunchObservation = serde_json::from_value(evidence.body.clone())
                .map_err(|_| PrivateOriginalError::Conflict)?;
            return match observed {
                WorkflowLaunchObservation::NotAdmitted => Ok(observed),
                _ => Err(PrivateOriginalError::Conflict),
            };
        }
        // This existing owner observes exact native input state and promotes
        // the same pending guard. A saved receipt by itself cannot do that.
        let observed = source
            .reconcile_original_submission(&self.submission.original)
            .await?;
        let Some(observed) = observed else {
            return Ok(WorkflowLaunchObservation::Native {
                observation: PrivateOriginalSubmission::AdmissionUnresolved,
            });
        };
        if !matches!(
            &observed,
            PrivateOriginalSubmission::Admitted {
                source_settlement: PrivateSourceSettlement::FreshAcceptancePromoted,
                ..
            }
        ) {
            return Ok(WorkflowLaunchObservation::Native {
                observation: observed,
            });
        }
        let held = source
            .retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .iter()
            .find(|held| held.reference == self.submission.original)
            .cloned()
            .ok_or(PrivateOriginalError::Unavailable)?;
        let workflow = held
            .setup_workflow
            .get()
            .ok_or(PrivateOriginalError::Unavailable)?;
        if workflow.reference != *snapshot.reference() {
            return Err(PrivateOriginalError::Conflict);
        }
        workflow.current_source()?;
        self.settle_launch_interest()?;
        if matches!(
            effect.status,
            EffectStatus::InFlight | EffectStatus::Uncertain
        ) || (effect.status == EffectStatus::Pending && effect.attempt > 0)
        {
            // The store atomically distinguishes a live claim from an expired
            // one, including InFlight with Some(expired lease). Never infer a
            // second dispatch from lease expiry or a lost acknowledgment.
            let claim = match source
                .store
                .claim_reconciliation(&key, "installed-workflow-observe", 60_000)
                .await
            {
                Ok(claim) => claim,
                Err(StoreError::Claimed | StoreError::EffectState) => {
                    return Ok(WorkflowLaunchObservation::Native {
                        observation: observed,
                    });
                }
                Err(error) => return Err(store_error(error)),
            };
            source
                .store
                .reconcile_effect(
                    &claim.lease.ok_or(PrivateOriginalError::Unavailable)?,
                    Reconciliation::Applied {
                        receipt: RecordData {
                            schema: "toolkit.setup-workflow-launch".into(),
                            version: 1,
                            body: serde_json::to_value(WorkflowLaunchObservation::Native {
                                observation: observed.clone(),
                            })
                            .map_err(|_| PrivateOriginalError::Conflict)?,
                        },
                    },
                )
                .await
                .map_err(store_error)?;
        }
        Ok(WorkflowLaunchObservation::Native {
            observation: observed,
        })
    }
}

impl PreparedWorkflowLaunch {
    pub(in crate::private_originals) fn selection(&self) -> &InstalledWorkflowPlanning {
        &self.selection
    }

    pub(in crate::private_originals) fn stage(
        &self,
        held: &Arc<HeldPrivateOriginal>,
        context: &GovernedBindContext,
    ) -> Result<Arc<HeldSetupWorkflow>, PrivateOriginalError> {
        let source = self
            .selection
            .source
            .upgrade()
            .ok_or(PrivateOriginalError::Unavailable)?;
        self.selection.check_for_binding(&source, &held.reference)?;
        let claims = held.original.association().candidate();
        if claims.target.context.as_str() != context.session_id.to_string()
            || claims.controller_model.as_ref() != Some(context.controller.selection())
            || claims.requester != self.selection.terms.requester
            || claims.ingress_namespace.realm != self.selection.terms.realm
        {
            return Err(PrivateOriginalError::Denied);
        }
        let route = context.controller.plain_facts().map_err(|_| PrivateOriginalError::Unavailable)?.route_key();
        let candidate = Arc::new(HeldSetupWorkflow {
            source: Arc::downgrade(&source),
            planning: held.original.clone(),
            reference: self.reference.clone(),
            member: self.selection.terms.lead.clone(),
            session: context.session_id.clone(),
            controller_route: route.clone(),
            accepted: AtomicBool::new(false),
            deadline_ms: self.selection.terms.deadline_ms,
            waiters: Mutex::new(Vec::new()),
        });
        let publication = source.owner.publication();
        let _change = publication
            .begin_owner_change()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let prior = held.setup_workflow.get_or_init(|| candidate);
        if prior.reference != self.reference
            || prior.session != context.session_id
            || prior.member != self.selection.terms.lead
            || !Arc::ptr_eq(&prior.planning, &held.original)
            || prior.controller_route != route
        {
            return Err(PrivateOriginalError::Conflict);
        }
        Ok(prior.clone())
    }

    async fn submit(
        self: &Arc<Self>,
        source: &Arc<PrivateOriginals>,
    ) -> Result<WorkflowLaunchObservation, PrivateOriginalError> {
        self.selection
            .check_for_binding(source, &self.selection.submission.original)?;
        let route = source.route(&self.selection.submission.original.route)?;
        let binder = self.binder(source, &route).await?;
        self.submit_with_binder(source, binder).await
    }

    async fn binder(
        self: &Arc<Self>,
        source: &Arc<PrivateOriginals>,
        route: &PrivateOriginalRoute,
    ) -> Result<Arc<WorkflowBinder>, PrivateOriginalError> {
        let delegate = OriginalBinder {
            source: source.clone(),
            grant: None,
            batch: None,
            original: self.selection.submission.original.clone(),
            held: OnceLock::new(),
            pending: OnceLock::new(),
            authentication: evidence(
                &route.authentication_domain,
                &self.selection.submission.transport_authentication,
            )?,
            event_key: source
                .original_event_key(&self.selection.submission.original)
                .await?,
            console: None,
            approved_login: None,
        };
        Ok(Arc::new(WorkflowBinder {
            delegate,
            planning: self.clone(),
        }))
    }

    async fn submit_with_binder(
        self: &Arc<Self>,
        source: &Arc<PrivateOriginals>,
        binder: Arc<dyn GovernedInputBinder>,
    ) -> Result<WorkflowLaunchObservation, PrivateOriginalError> {
        self.selection
            .check_for_binding(source, &self.selection.submission.original)?;
        let route = source.route(&self.selection.submission.original.route)?;
        let runtime = source.bound_identity_runtime()?;
        let alias = route.grant_target.as_str();
        let identity = runtime
            .owned_identity_for_member_alias(alias)
            .await
            .ok_or(PrivateOriginalError::Unavailable)?;
        let input = Input::Prompt(PromptInput::new(
            self.selection.submission.content.clone(),
            None,
        ));
        let dedicated = source.owner.dedicated_workflow_session(
            &self.reference, &self.selection.terms.lead,
            &self.selection.submission.original.original,
        ).map_err(custody_error)?;
        let result = if dedicated.is_some() {
            runtime.dispatch_governed_with_turn_ticket(&identity, Some(alias), input, binder).await
        } else {
            runtime.send_governed_with_turn_ticket(&identity, Some(alias), input, binder).await
        };
        Ok(match result {
            Ok(outcome) => WorkflowLaunchObservation::Native {
                observation: PrivateOriginalSubmission::Admitted {
                    session_id: outcome.admission.session_id.to_string(),
                    input_id: outcome.admission.input_id.to_string(),
                    deduplicated: outcome.admission.deduplicated,
                    turn_ticket: match outcome.ticketed.turn {
                        TurnTracking::Tracked(ticket) => Some(ticket.to_string()),
                        _ => None,
                    },
                    source_settlement: if outcome.admission.deduplicated {
                        PrivateSourceSettlement::RetryWithdrawn
                    } else if outcome.settlement.is_ok() {
                        PrivateSourceSettlement::FreshAcceptancePromoted
                    } else {
                        PrivateSourceSettlement::PostAdmissionPublicationFailed
                    },
                },
            },
            // Exact selected Meta returns Bind before creating native admission
            // custody or calling the bridge. Mob follows NotAdmitted custody,
            // and EntryRefused follows a fence that prevented submission.
            Err(IdentityRuntimeError::GovernedInput(
                GovernedInputError::Bind(_)
                | GovernedInputError::Mob(_)
                | GovernedInputError::EntryRefused(_),
            )) => WorkflowLaunchObservation::NotAdmitted,
            Err(IdentityRuntimeError::GovernedInput(GovernedInputError::AdmissionUnresolved {
                ..
            })) => WorkflowLaunchObservation::Native {
                observation: PrivateOriginalSubmission::AdmissionUnresolved,
            },
            Err(_) => WorkflowLaunchObservation::Native {
                observation: PrivateOriginalSubmission::NativeOutcomeUnavailable,
            },
        })
    }
}

struct WorkflowBinder {
    delegate: OriginalBinder,
    planning: Arc<PreparedWorkflowLaunch>,
}
#[async_trait::async_trait]
impl GovernedInputBinder for WorkflowBinder {
    async fn bind(
        &self,
        context: &GovernedBindContext,
        input: Input,
    ) -> Result<BoundGovernedInput, String> {
        let source = self.planning.selection.source.upgrade()
            .ok_or_else(|| "The workflow source owner is unavailable".to_owned())?;
        if let Some(session) = source.owner.dedicated_workflow_session(
            &self.planning.reference, &self.planning.selection.terms.lead,
            &self.planning.selection.submission.original.original,
        ).map_err(|_| "The dedicated workflow member is unavailable".to_owned())? {
            if session != context.session_id || context.spec.addressability !=
                meerkat_mobkit::identity_first::AgentAddressability::InternalOnly {
                return Err("The dedicated workflow member changed".into());
            }
        }
        let mut bound = self
            .delegate
            .bind_retained_with_workflow(context, input, Some(&self.planning))
            .await?;
        if bound.entry_fence.is_some() {
            return Err("The planning input has a conflicting entry owner".into());
        }
        bound.entry_fence = Some(Arc::new(LaunchFence {
            planning: self.planning.selection.clone(),
        }));
        Ok(bound)
    }
    fn retain_unresolved(&self, settlement: Box<dyn GovernedSettlement>, detail: &str) {
        self.delegate.retain_unresolved(settlement, detail);
    }
}

/// Native invokes this after every bind/member await. SharedEntry's same
/// local lock orders each close against entry. Any one still-current waiter
/// is sufficient; waiters never become G contributing-work conjuncts.
struct LaunchFence {
    planning: Arc<InstalledWorkflowPlanning>,
}
impl GovernedEntryFence for LaunchFence {
    fn enter(&self) -> Result<Box<dyn GovernedEntryPermit>, GovernedEntryRefusal> {
        let source = self.planning.source.upgrade().ok_or_else(|| {
            GovernedEntryRefusal::Unavailable("The planning source owner is unavailable".into())
        })?;
        let mut interests = self.planning.interests.lock().map_err(|_| {
            GovernedEntryRefusal::Unavailable("The planning interests are unavailable".into())
        })?;
        let now = source
            .owner
            .clock()
            .now()
            .map_err(|_| {
                GovernedEntryRefusal::Unavailable("The planning clock is unavailable".into())
            })?
            .unix_ms;
        if now >= self.planning.terms.deadline_ms {
            return Err(GovernedEntryRefusal::Expired);
        }
        let mut unavailable = false;
        for interest in interests.iter_mut() {
            if interest.closed || now >= interest.membership.deadline_ms() {
                continue;
            }
            let Some(original) = &interest.original else { continue; };
            match source.owner.enter_workflow_launch(original) {
                Ok(entry) => {
                    interest.entries.push(entry.clone());
                    return Ok(Box::new(LaunchPermit { entry }));
                }
                Err(crate::original_ingress::OriginalWriterError::OperationCancelled) => continue,
                // A pending/failed cancellation is not eligible interest,
                // but it must not block another independently current waiter.
                // Only that waiter's actual successful entry can admit G.
                Err(_) => unavailable = true,
            }
        }
        // No source reservation was created and native has not admitted it.
        // Preserve uncertainty if none of the independent entries succeeded.
        if unavailable {
            Err(GovernedEntryRefusal::Unavailable(
                "The waiter entry owner is unavailable".into(),
            ))
        } else {
            Err(GovernedEntryRefusal::Retired)
        }
    }
}
struct LaunchPermit {
    entry: Arc<crate::original_ingress::shared_entry::SharedEntry>,
}
impl GovernedEntryPermit for LaunchPermit {
    fn finish(self: Box<Self>, outcome: GovernedEntryOutcome) {
        // A lost/uncertain decision remains in both native input custody and
        // the actual source reservations. No Drop path fabricates settlement.
        if !matches!(outcome, GovernedEntryOutcome::Uncertain) {
            let _ = self.entry.settle();
        }
    }
}

impl HeldSetupWorkflow {
    pub(in crate::private_originals) fn accepted(&self) -> Result<(), PrivateOriginalError> {
        let source = self
            .source
            .upgrade()
            .ok_or(PrivateOriginalError::Unavailable)?;
        let publication = source.owner.publication();
        let _change = publication
            .begin_owner_change()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let controller = source
            .owner
            .workflow_controller(&self.planning)
            .map_err(custody_error)?;
        if controller.plain_facts().map_err(|_| PrivateOriginalError::Unavailable)?.route_key() != self.controller_route {
            return Err(PrivateOriginalError::Conflict);
        }
        self.accepted.store(true, Ordering::Release);
        Ok(())
    }
}

fn same_optional(
    a: Option<&Arc<InstalledWorkflowPlanning>>,
    b: Option<&Arc<InstalledWorkflowPlanning>>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            Arc::ptr_eq(&a.parent, &b.parent)
                && Weak::ptr_eq(&a.source, &b.source)
                && a.terms == b.terms
                && a.lineage == b.lineage
                && a.submission.original == b.submission.original
                && a.submission.content == b.submission.content
                && a.submission.transport_authentication == b.submission.transport_authentication
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
