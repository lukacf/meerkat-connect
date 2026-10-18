//! Shared physical preparation is joined by the existing captured source.
//! This owner retains cleanup custody before the single P-record CAS; it does
//! not convert package observations into software approval or native grants.
use super::*;
use meerkat_toolkit::setup::{
    SetupWorkBackend, SharedPreparationCompletion, SharedPreparationMember,
    SharedPreparationSelection,
};

const MAX_SOURCE_PREPARATIONS: usize = 128;

/// A live resource attachment on the existing retained source. Canonical P
/// supplies the member/last-member decision. This callback only reaches the
/// exact currently owned Controller; it has no wire constructor or membership.
#[async_trait::async_trait]
pub trait SharedPreparationResource: Send + Sync {
    /// Observe only this member's exact physical worker after its natural join.
    /// Missing/restarted custody stays unavailable, never a fabricated result.
    async fn completion(
        &self,
        preparation: &str,
        selection: &SharedPreparationSelection,
    ) -> Result<Option<SharedPreparationCompletion>, PrivateOriginalError>;
    /// Retain this exact source-owned leave through caller loss before polling
    /// its first CAS. The resource owns execution, not the membership decision.
    async fn retain_leave(
        &self,
        leave: SharedPreparationLeave,
    ) -> Result<serde_json::Value, PrivateOriginalError>;

    /// Return only after this member is detached and, for the last member,
    /// the actual physical worker is joined. Missing or pending custody refuses.
    async fn leave(
        &self,
        preparation: &str,
        selection: &SharedPreparationSelection,
        last: bool,
    ) -> Result<serde_json::Value, PrivateOriginalError>;
}

pub(in crate::private_originals) struct HeldSharedPreparation {
    member: SharedPreparationMember,
    resource: Arc<dyn SharedPreparationResource>,
    selection: SharedPreparationSelection,
}

/// A source-owned membership, not an effect permit. The native caller must
/// still authorize its exact operation and the software owner must review it.
/// There is no wire constructor and no model-supplied source or group lookup.
#[derive(Clone)]
pub struct InstalledSharedPreparation {
    task: InstalledServiceTask,
    member: SharedPreparationMember,
    backend: SetupWorkBackend,
}

/// An already selected source-owned leave. Only the canonical source can
/// construct it. The live resource must retain and join it before returning;
/// accepting this value grants no native operation or membership authority.
pub struct SharedPreparationLeave {
    member: InstalledSharedPreparation,
}
impl SharedPreparationLeave {
    pub async fn settle(self) -> Result<serde_json::Value, PrivateOriginalError> {
        self.member.leave_owned().await
    }
}

impl InstalledServiceTask {
    /// Called only with the real Controller's private selected-check response.
    /// Source retention precedes P admission so uncertain join still has one
    /// existing cleanup owner. No transaction across source and P is implied.
    pub(crate) async fn join_shared_preparation(
        &self,
        selection: &SharedPreparationSelection,
        backend: SetupWorkBackend,
        resource: Arc<dyn SharedPreparationResource>,
    ) -> Result<InstalledSharedPreparation, PrivateOriginalError> {
        let member = self
            .source
            .owner
            .retain_followup_source(&self.parent_association, || async {
                let (stored, snapshot) = self
                    .current()
                    .await
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                let scope = self.scope().map_err(|_| OriginalWriterError::Conflict)?;
                let setup = SetupStore::new_conditional(self.store.as_ref(), scope)
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                let member = setup
                    .shared_preparation_member(&snapshot, stored.key.clone(), selection)
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                // Retain live cleanup custody before publishing even an
                // uncertain source/P join. It does not establish membership.
                self.source
                    .retain_shared_resource(
                        &self.parent_association,
                        &member,
                        selection,
                        resource.clone(),
                    )
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                let mut record = self
                    .source
                    .decode_record(&stored, &self.parent)
                    .map_err(|_| OriginalWriterError::Conflict)?;
                if !record.shared_preparations.contains(&member) {
                    if record.shared_preparations.len() >= MAX_SOURCE_PREPARATIONS {
                        return Err(OriginalWriterError::Unavailable);
                    }
                    record.shared_preparations.push(member.clone());
                    let data = encode(record.clone()).map_err(|_| OriginalWriterError::Conflict)?;
                    // A lost source write is resolved through this same row before
                    // any P join or Controller disclosure is attempted.
                    let written = self
                        .source
                        .store
                        .compare_and_swap(Transition {
                            key: stored.key.clone(),
                            expected_revision: stored.revision,
                            expected_digest: Some(stored.content_digest),
                            claim: None,
                            data,
                            events: vec![],
                            effects: vec![],
                        })
                        .await;
                    let saved = match written {
                        Ok(saved) => saved,
                        Err(_) => self
                            .source
                            .store
                            .get(&stored.key)
                            .await
                            .map_err(|_| OriginalWriterError::Unavailable)?
                            .ok_or(OriginalWriterError::Unavailable)?,
                    };
                    if self
                        .source
                        .decode_record(&saved, &self.parent)
                        .map_err(|_| OriginalWriterError::Conflict)?
                        != record
                    {
                        return Err(OriginalWriterError::Unavailable);
                    }
                }
                setup
                    .join_shared_preparation(&member, selection, &backend)
                    .await
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                // The source writer still fences cancellation while P is joined.
                // Its release is not a reusable currentness or entry reservation.
                self.current()
                    .await
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                Ok(member)
            })
            .await
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        Ok(InstalledSharedPreparation {
            task: self.clone(),
            member,
            backend,
        })
    }
}

impl InstalledSharedPreparation {
    /// An opaque correlation for the host-private Controller handoff. The
    /// Controller cannot validate membership from this string on its own.
    pub fn preparation_identity(&self) -> &str {
        &self.member.key().id
    }

    async fn observe_completion(&self) -> Result<(), PrivateOriginalError> {
        let (resource, selection) = self.task.source.shared_resource(&self.member)?;
        let Some(completion) = resource
            .completion(self.preparation_identity(), &selection)
            .await?
        else {
            return Ok(());
        };
        self.task
            .source
            .owner
            .retain_followup_source(&self.task.parent_association, || async {
                self.check_current()
                    .await
                    .map_err(|_| OriginalWriterError::OperationDenied)?;
                let setup = SetupStore::new_conditional(
                    self.task.store.as_ref(),
                    self.task
                        .scope()
                        .map_err(|_| OriginalWriterError::Conflict)?,
                )
                .map_err(|_| OriginalWriterError::Unavailable)?;
                setup
                    .complete_shared_preparation(&self.member, &completion, &self.backend)
                    .await
                    .map_err(|_| OriginalWriterError::Unavailable)
            })
            .await
            .map_err(|_| PrivateOriginalError::Unavailable)
    }

    /// Invoked only after the exact native setup_stop call entered and returned
    /// the Controller's member-leave handoff. Source cancellation uses the same
    /// retained resource below. The P writer, not this callback, decides last.
    async fn leave(&self) -> Result<serde_json::Value, PrivateOriginalError> {
        let (resource, _) = self.task.source.shared_resource(&self.member)?;
        // Schedule through the existing live resource before any source/P CAS.
        // Caller loss can now lose the reply, but not the accepted leave chain.
        resource
            .retain_leave(SharedPreparationLeave {
                member: self.clone(),
            })
            .await
    }

    async fn leave_owned(&self) -> Result<serde_json::Value, PrivateOriginalError> {
        let entries = self
            .task
            .source
            .owner
            .retain_followup_source(&self.task.parent_association, || async {
                let (stored, _) = self
                    .task
                    .current()
                    .await
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                let record = self
                    .task
                    .source
                    .decode_record(&stored, &self.task.parent)
                    .map_err(|_| OriginalWriterError::Conflict)?;
                if !record.shared_preparations.contains(&self.member) {
                    return Err(OriginalWriterError::WrongOwner);
                }
                let entries = self.task.source.owner.close_shared_member_entries(
                    &self.task.parent_association,
                    self.preparation_identity(),
                )?;
                let setup = SetupStore::new_conditional(
                    self.task.store.as_ref(),
                    self.task
                        .scope()
                        .map_err(|_| OriginalWriterError::Conflict)?,
                )
                .map_err(|_| OriginalWriterError::Unavailable)?;
                setup
                    .begin_shared_preparation_leave(&self.member)
                    .await
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                Ok(entries)
            })
            .await
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        // No writer or identity lock spans a native admission decision.
        ToolkitOriginalOwner::drain_shared_entries(entries)
            .await
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let setup = SetupStore::new_conditional(self.task.store.as_ref(), self.task.scope()?)
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let last = setup
            .leave_shared_preparation(&self.member)
            .await
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        self.task
            .source
            .leave_shared_resource(&self.member, last)
            .await
    }

    /// Reopen both canonical owners immediately before reserving native entry.
    /// The subsequent synchronous source gate must still order cancellation.
    pub async fn check_current(&self) -> Result<(), PrivateOriginalError> {
        let (stored, snapshot) = self.task.current().await?;
        let record = self.task.source.decode_record(&stored, &self.task.parent)?;
        if !record.shared_preparations.contains(&self.member)
            || self.member.source() != &stored.key
            || self.member.acquisition() != snapshot.key()
        {
            return Err(PrivateOriginalError::Denied);
        }
        let setup = SetupStore::new_conditional(self.task.store.as_ref(), self.task.scope()?)
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        setup
            .check_shared_preparation(&self.member, &self.backend)
            .await
            .map_err(|_| PrivateOriginalError::Denied)?;
        self.task.current().await?;
        Ok(())
    }
}

/// Ephemeral custody between the native final check and the Controller's
/// initial dispatch decision. It grants no operation and has no wire form.
#[derive(Clone)]
pub struct InstalledSharedEntry {
    entry: Arc<crate::original_ingress::shared_entry::SharedEntry>,
}
impl InstalledSharedEntry {
    /// Called by the exact native MCP final check immediately before send.
    /// A source cancellation closes this same gate before acknowledgement.
    pub fn enter(&self) -> Result<(), PrivateOriginalError> {
        self.entry.enter().map_err(|_| PrivateOriginalError::Denied)
    }
    pub async fn closed(&self) {
        self.entry.closed().await;
    }
    /// Settle only after the private Controller owner reports entered or
    /// definite nonentry. Missing/lost replies must retain unresolved custody.
    pub fn settle(&self) -> Result<(), PrivateOriginalError> {
        self.entry
            .settle()
            .map_err(|_| PrivateOriginalError::Unavailable)
    }
}

impl InstalledServiceTask {
    pub(crate) async fn complete_shared_preparation(
        &self,
        member: &InstalledSharedPreparation,
    ) -> Result<(), PrivateOriginalError> {
        if !self.owns_shared_member(member) {
            return Err(PrivateOriginalError::Denied);
        }
        member.observe_completion().await
    }

    pub(crate) async fn leave_shared_preparation(
        &self,
        member: &InstalledSharedPreparation,
    ) -> Result<serde_json::Value, PrivateOriginalError> {
        if !self.owns_shared_member(member) {
            return Err(PrivateOriginalError::Denied);
        }
        member.leave().await
    }

    fn owns_shared_member(&self, member: &InstalledSharedPreparation) -> bool {
        Arc::ptr_eq(&self.source, &member.task.source)
            && self.parent_association == member.task.parent_association
            && self.parent == member.task.parent
            && self.acquisition == member.task.acquisition
            && self.input_digest == member.task.input_digest
    }

    pub(crate) async fn reserve_shared_entry(
        &self,
        member: Option<&InstalledSharedPreparation>,
    ) -> Result<InstalledSharedEntry, PrivateOriginalError> {
        self.source
            .owner
            .retain_followup_source(&self.parent_association, || async {
                self.current()
                    .await
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                if let Some(member) = member {
                    if !self.owns_shared_member(member) {
                        return Err(OriginalWriterError::WrongOwner);
                    }
                    member
                        .check_current()
                        .await
                        .map_err(|_| OriginalWriterError::OperationDenied)?;
                }
                let entry = self.source.owner.retain_shared_entry(
                    &self.parent_association,
                    member.map(|member| member.preparation_identity()),
                )?;
                Ok(InstalledSharedEntry { entry })
            })
            .await
            .map_err(|_| PrivateOriginalError::Denied)
    }
}

impl PrivateOriginals {
    /// Native continuation verification has already authenticated this exact
    /// receipt. Persist its historical P observation before the existing
    /// acquisition outbox acknowledges it. This never opens membership or sends
    /// an input, and a departed member still retains its earlier admission.
    pub(crate) async fn record_shared_continuation_admission(
        &self,
        obligation: &meerkat_toolkit::continuation::ContinuationObligation,
        evidence: &meerkat_toolkit::continuation::ContinuationAdmissionEvidence,
    ) -> Result<(), meerkat_toolkit::continuation::ContinuationError> {
        use meerkat_toolkit::continuation::ContinuationError;
        let setup = self
            .service_setup_store()
            .map_err(|_| ContinuationError::OwnerUnavailable)?;
        let original = obligation
            .continuation()
            .native_original
            .as_ref()
            .ok_or(ContinuationError::Unsupported)?;
        let snapshot = setup
            .service_task_snapshot(obligation.operation(), original)
            .await
            .map_err(|_| ContinuationError::OwnerUnavailable)?;
        if snapshot.request().host().work_context.is_none() {
            return Ok(());
        }
        let association = snapshot.request().evidence().association();
        let reference = self
            .retained
            .lock()
            .map_err(|_| ContinuationError::OwnerUnavailable)?
            .iter()
            .find(|held| held.original.association() == association)
            .map(|held| held.reference.clone())
            .ok_or(ContinuationError::OwnerUnavailable)?;
        let key = self
            .key(&reference)
            .map_err(|_| ContinuationError::InvalidReceipt)?;
        let stored = self
            .store
            .get(&key)
            .await
            .map_err(|_| ContinuationError::OwnerUnavailable)?
            .ok_or(ContinuationError::OwnerUnavailable)?;
        let record = self
            .decode_record(&stored, &reference)
            .map_err(|_| ContinuationError::InvalidReceipt)?;
        if record.final_association.as_ref() != Some(association) {
            return Err(ContinuationError::InvalidReceipt);
        }
        for member in &record.shared_preparations {
            if member.acquisition() != snapshot.key() {
                continue;
            }
            if member.source() != &key {
                return Err(ContinuationError::InvalidReceipt);
            }
            setup
                .acknowledge_shared_preparation_delivery(member, evidence)
                .await
                .map_err(|_| ContinuationError::OwnerUnavailable)?;
        }
        Ok(())
    }

    fn retain_shared_resource(
        &self,
        association: &meerkat_authorization_contracts::work_association::InputAuthorityAssociation,
        member: &SharedPreparationMember,
        selection: &SharedPreparationSelection,
        resource: Arc<dyn SharedPreparationResource>,
    ) -> Result<(), PrivateOriginalError> {
        let held = self
            .retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .iter()
            .find(|held| held.original.association() == association)
            .cloned()
            .ok_or(PrivateOriginalError::Unavailable)?;
        if self.key(&held.reference)? != *member.source() {
            return Err(PrivateOriginalError::Denied);
        }
        let mut resources = held
            .shared_preparations
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        if let Some(prior) = resources.iter().find(|value| &value.member == member) {
            return if Arc::ptr_eq(&prior.resource, &resource) && &prior.selection == selection {
                Ok(())
            } else {
                Err(PrivateOriginalError::Conflict)
            };
        }
        if resources.len() >= MAX_SOURCE_PREPARATIONS {
            return Err(PrivateOriginalError::Unavailable);
        }
        resources.push(HeldSharedPreparation {
            member: member.clone(),
            resource,
            selection: selection.clone(),
        });
        Ok(())
    }

    pub(super) async fn leave_shared_resource(
        &self,
        member: &SharedPreparationMember,
        last: bool,
    ) -> Result<serde_json::Value, PrivateOriginalError> {
        let (resource, selection) = self.shared_resource(member)?;
        // A restored row without this exact live attachment is unresolved.
        resource.leave(&member.key().id, &selection, last).await
    }

    fn shared_resource(
        &self,
        member: &SharedPreparationMember,
    ) -> Result<
        (
            Arc<dyn SharedPreparationResource>,
            SharedPreparationSelection,
        ),
        PrivateOriginalError,
    > {
        let retained = self
            .retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let held = retained
            .iter()
            .find(|held| self.key(&held.reference).as_ref() == Ok(member.source()))
            .ok_or(PrivateOriginalError::Unavailable)?;
        let resources = held
            .shared_preparations
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let selected = resources
            .iter()
            .find(|value| &value.member == member)
            .ok_or(PrivateOriginalError::Unavailable)?;
        Ok((selected.resource.clone(), selected.selection.clone()))
    }
}
