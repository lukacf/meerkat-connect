//! One approved B source may replace A's result delivery. These are canonical
//! correlations and historical admission observations, never authority for A.
use super::*;
use meerkat_authorization_contracts::work_association::OriginalWorkRef;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedServiceSelection {
    pub source: StoreKey,
    pub original_work: OriginalWorkRef,
    /// Digest of the source owner's immutable source, event and reviewed task
    /// link. Mutable cancellation/publication fields are not selection inputs.
    pub source_identity: ContentDigest,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedServiceInput {
    pub source_admission: ContextReference,
    pub runtime: Id,
    pub session: Id,
    pub input: Id,
}

/// Port on the existing approved-source owner. The host supplies it; serialized
/// selections and receipts cannot choose this implementation or prove access.
#[async_trait]
pub trait ApprovedServiceSourceOwner: Send + Sync {
    async fn verify_selection(&self, snapshot: &SetupSnapshot, selected: &ApprovedServiceSelection)
        -> Result<(), SetupError>;
    async fn observe_admission(&self, snapshot: &SetupSnapshot, selected: &ApprovedServiceSelection)
        -> Result<Option<ApprovedServiceInput>, SetupError>;
    /// Both historical non-entry and a durable fence against later entry are
    /// required. Current denial or an absent native lookup is insufficient.
    async fn observe_rejection(&self, snapshot: &SetupSnapshot, selected: &ApprovedServiceSelection)
        -> Result<Option<ContextReference>, SetupError>;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovedServiceReady {
    pub selection_digest: ContentDigest,
    pub selection_generation: u64,
    pub observed_at_ms: u64,
    pub admission: ApprovedServiceInput,
}

impl SetupSnapshot {
    pub fn approved_service(&self) -> Option<&ApprovedServiceSelection> {
        self.record.approved_service.as_ref()
    }
    pub fn approved_service_was_admitted(&self) -> bool {
        self.record.service_ready.is_some()
    }
}

impl SetupStore<'_> {
    /// Only the selected source owner can report that B definitely never
    /// entered and can no longer enter. Generic/helper result writers cannot
    /// replace the reserved continuation with their own terminal observation.
    pub async fn reject_approved_service(
        &self, snapshot: &SetupSnapshot, owner: &dyn ApprovedServiceSourceOwner,
    ) -> Result<SetupSnapshot, SetupError> {
        self.scope.check(&snapshot.request)?;
        let selected = snapshot.approved_service().ok_or(SetupError::Rejected)?;
        let detail = owner.observe_rejection(snapshot, selected).await?
            .ok_or(ContinuationError::OwnerUnavailable)?;
        if !matches!(snapshot.state().lifecycle_phase, AcquisitionPhase::Investigating | AcquisitionPhase::Preparing) {
            return Ok(snapshot.clone());
        }
        let now = u64::try_from(self.store.now_ms().await?).map_err(|_| SetupError::InvalidRecord)?;
        let state = snapshot.state();
        let (mut record, effects) = apply_selected_source(snapshot, AcquisitionInput::ReportUnavailable {
            operation_id: state.operation_id.clone(), authority_digest: state.authority_digest.clone(),
            expected_revision: state.revision, detail_ref: digest(&detail)?.to_string(), now,
        })?;
        record.detail = Some(detail);
        self.commit(snapshot, record, effects, None).await
    }

    /// Reserve B before its attachment/input entry. A failed CAS cannot select
    /// another source implicitly. Identical retries read the canonical winner.
    pub async fn reserve_approved_service(
        &self, snapshot: &SetupSnapshot, selected: ApprovedServiceSelection,
        owner: &dyn ApprovedServiceSourceOwner,
    ) -> Result<SetupSnapshot, SetupError> {
        self.scope.check(&snapshot.request)?;
        owner.verify_selection(snapshot, &selected).await?;
        if let Some(prior) = &snapshot.record.approved_service {
            return if prior == &selected { Ok(snapshot.clone()) } else { Err(SetupError::Rejected) };
        }
        // Never reinterpret an already selected A-role implementation as B.
        if !snapshot.record.selections.is_empty() { return Err(SetupError::Rejected); }
        let state = snapshot.state();
        let selected_digest = digest(&selected)?.to_string();
        let now = u64::try_from(self.store.now_ms().await?).map_err(|_| SetupError::InvalidRecord)?;
        let (mut record, effects) = apply(snapshot, AcquisitionInput::RecordSelection {
            operation_id: state.operation_id.clone(), authority_digest: state.authority_digest.clone(),
            expected_revision: state.revision, selection_digest: selected_digest.clone(),
            decision_ref: selected_digest, now,
        })?;
        record.approved_service = Some(selected);
        self.commit(snapshot, record, effects, None).await
    }

    /// Commit setup completion only from B's actual durable source admission.
    /// A's frozen authority and original continuation are not rewritten. The
    /// generated owner retains cancellation/deadline precedence and emits the
    /// same outbox intent; its delivery owner observes B instead of submitting A.
    pub async fn observe_approved_service(
        &self, snapshot: &SetupSnapshot, owner: &dyn ApprovedServiceSourceOwner,
    ) -> Result<SetupSnapshot, SetupError> {
        self.scope.check(&snapshot.request)?;
        let selected = snapshot.approved_service().ok_or(SetupError::Rejected)?;
        let admission = owner.observe_admission(snapshot, selected).await?
            .ok_or(ContinuationError::OwnerUnavailable)?;
        if let Some(prior) = &snapshot.record.service_ready {
            return if prior.admission == admission { Ok(snapshot.clone()) }
                else { Err(SetupError::InvalidRecord) };
        }
        // A terminal cancellation/failure remains terminal even if B's earlier
        // native admission is published later. Its B selection still prevents
        // a second delivery in the continuation owner.
        if !matches!(snapshot.state().lifecycle_phase, AcquisitionPhase::Investigating | AcquisitionPhase::Preparing) {
            return Ok(snapshot.clone());
        }
        let now = u64::try_from(self.store.now_ms().await?).map_err(|_| SetupError::InvalidRecord)?;
        let state = snapshot.state();
        let ready = ApprovedServiceReady { selection_digest: digest(selected)?,
            selection_generation: state.selection_generation, observed_at_ms: now, admission };
        let readiness_digest = digest(&ready)?.to_string();
        let (mut record, effects) = apply(snapshot, AcquisitionInput::ResolveReady {
            operation_id: state.operation_id.clone(), authority_digest: state.authority_digest.clone(),
            expected_revision: state.revision, selection_digest: state.selection_digest.clone(),
            selection_generation: state.selection_generation, readiness_ref: readiness_digest.clone(),
            readiness_digest, observed_at: now, now,
        })?;
        record.service_ready = Some(ready);
        self.commit(snapshot, record, effects, None).await
    }
}
