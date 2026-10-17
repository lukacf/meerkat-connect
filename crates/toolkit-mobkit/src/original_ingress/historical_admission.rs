//! Historical task custody enters only from the native admitted-original callback.
//! No source publication waits while the native B/M/driver owners are held.
use super::*;
use meerkat_runtime::meerkat_machine::AdmittedOriginal;

impl ToolkitOriginalOwner {
    /// Try the existing source writer without waiting. Canonical evidence reads
    /// release it before native observation; the synchronous callback reacquires
    /// it and retains it through the nonblocking publication/originals checks.
    pub(crate) fn try_source_writer(&self)
        -> Result<tokio::sync::MutexGuard<'_, ()>, OriginalWriterError>
    {
        self.mutation.try_lock().map_err(|_| OriginalWriterError::Unavailable)
    }

    /// Warm custody remains the existing native resume path, including source
    /// classes outside the narrow cold reconstruction. This is no permission
    /// check: native still checks the complete contributor closure and grants.
    pub(crate) fn has_admitted_source(&self, association: &InputAuthorityAssociation)
        -> Result<bool, OriginalWriterError>
    {
        let originals = self.originals.try_lock().map_err(|_| OriginalWriterError::Unavailable)?;
        let claims = association.candidate();
        let Some(record) = originals.iter().find(|row|
            row.names(&claims.ingress_namespace.realm, &claims.original_work)) else { return Ok(false); };
        let OriginalRecord::Bound(held) = record else { return Ok(false); };
        if held.association() != association { return Err(OriginalWriterError::Conflict); }
        match &held.operation {
            OriginalOperationDisposition::Open => (),
            OriginalOperationDisposition::CancellationPending => return Err(OriginalWriterError::Unavailable),
            OriginalOperationDisposition::Cancelled { .. } => return Err(OriginalWriterError::OperationCancelled),
        }
        Ok(held.source_custody == Some(SourceCustody::Admitted)
            && held.controller.as_ref().is_some_and(|client|
                claims.controller_model.as_ref() == Some(client.selection())))
    }

    /// Preserve restore_authenticated's task-child check, including the legacy
    /// single-lineage resolution. Called before entering native B/M/D.
    pub(crate) fn check_historical_task_child(&self, association: &InputAuthorityAssociation)
        -> Result<(), OriginalWriterError>
    {
        self.check_original_child(association)
    }

    /// Recheck the exact candidate before retaining its bound Input. The caller
    /// holds the source writer across its durable evidence write.
    pub(crate) fn check_bound_source(&self, original: &Arc<RetainedToolkitOriginal>)
        -> Result<(), OriginalWriterError>
    {
        self.require_retained(original)?;
        self.refuse_cancelled_binding(original.association())
    }

    /// Called only after the canonical approved B decision or selected setup A
    /// child binding was joined under this owner's writer. Native supplies the
    /// actual admitted association/controller, never a decoded input capability.
    /// This changes source custody only: all native phases stay historical.
    pub(crate) fn promote_historical_task(
        &self,
        association: &InputAuthorityAssociation,
        custody: AuthenticatedOriginal,
        sources: &[OriginalCancellationSource],
        admitted: &AdmittedOriginal<'_>,
    ) -> Result<Arc<RetainedToolkitOriginal>, OriginalWriterError> {
        self.check_source(association, &custody,
            &association.candidate().requester, &association.candidate().ingress_actor)?;
        if admitted.association() != association
            || association.candidate().controller_model.as_ref() != Some(admitted.controller().selection())
            || association.candidate().target.logical_runtime.as_str()
                != meerkat_runtime::LogicalRuntimeId::for_session(admitted.session_id()).to_string()
        { return Err(OriginalWriterError::Conflict); }
        // Required lock order inside native B/M/D: non-waiting publication,
        // then non-waiting source collection. Neither failure mutates custody.
        let _publication = self.publication.try_begin_owner_change()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        let mut originals = self.originals.try_lock()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        for source in sources {
            if let Some(retained) = originals.iter().find(|entry| entry.names(&source.realm, &source.original)) {
                let operation = match retained {
                    OriginalRecord::Bound(held) => {
                        if source.association.as_ref() != Some(held.association()) {
                            return Err(OriginalWriterError::Conflict);
                        }
                        &held.operation
                    }
                    OriginalRecord::UnboundCancellation { source_record, operation, .. } => {
                        if !crate::private_originals::same_source_origin(source_record, &source.record) {
                            return Err(OriginalWriterError::Conflict);
                        }
                        operation
                    }
                };
                match operation {
                    OriginalOperationDisposition::Open => (),
                    OriginalOperationDisposition::CancellationPending => return Err(OriginalWriterError::Unavailable),
                    OriginalOperationDisposition::Cancelled { .. } => return Err(OriginalWriterError::OperationCancelled),
                }
            }
        }
        Self::check_task_lineage_isolation(association, &originals)?;
        let claims = association.candidate();
        if let Some(record) = originals.iter_mut().find(|entry|
            entry.names(&claims.ingress_namespace.realm, &claims.original_work))
        {
            let OriginalRecord::Bound(held) = record else { return Err(OriginalWriterError::Unavailable); };
            if held.association() != association || !matches!(held.grant_binding, OriginalGrantBinding::Task { .. } | OriginalGrantBinding::ServiceSet { .. }) {
                return Err(OriginalWriterError::Conflict);
            }
            if held.source_custody == Some(SourceCustody::Candidate) {
                // The warm native settlement still owns this guard.
                return Err(OriginalWriterError::Unavailable);
            }
            held.source_custody = Some(SourceCustody::Admitted);
            held.controller = Some(admitted.controller().clone());
            return Ok(held.retained.clone());
        }
        let retained = Arc::new(RetainedToolkitOriginal {
            association: association.clone(), custody,
            // Historical admission does not recover a task-revoke issuer.
            grant_binding: OriginalGrantBinding::Task { issuer: None },
        });
        originals.push(OriginalRecord::Bound(HeldOriginal {
            retained: retained.clone(), source_custody: Some(SourceCustody::Admitted),
            controller: Some(admitted.controller().clone()), service_set_admission: None, operation: OriginalOperationDisposition::Open,
        }));
        Ok(retained)
    }
}

#[cfg(test)]
impl ToolkitOriginalOwner {
    /// Simulate loss of this fixture's B process custody, not durable/native
    /// state or a full process restart. Production has no row-removal API.
    pub(crate) fn forget_task_custody_for_test(&self, association: &InputAuthorityAssociation) {
        let _publication = self.publication.begin_owner_change().unwrap();
        let mut originals = self.originals.lock().unwrap();
        let index = originals.iter().position(|entry|
            entry.bound().is_some_and(|held| held.association() == association)).unwrap();
        let held = originals[index].bound().unwrap();
        assert!(matches!(held.grant_binding, OriginalGrantBinding::Task { .. } | OriginalGrantBinding::ServiceSet { .. }));
        assert!(held.source_custody != Some(SourceCustody::Candidate));
        originals.remove(index);
    }

    pub(crate) fn historical_task_custody_for_test(&self, association: &InputAuthorityAssociation)
        -> Option<(bool, bool)>
    {
        self.originals.lock().unwrap().iter().filter_map(OriginalRecord::bound)
            .find(|held| held.association() == association).map(|held| (
                held.source_custody == Some(SourceCustody::Admitted),
                matches!(held.grant_binding, OriginalGrantBinding::Task { issuer: None }),
            ))
    }

    pub(crate) fn lock_originals_for_test(&self) -> impl Drop + '_ {
        self.originals.lock().unwrap()
    }
}
