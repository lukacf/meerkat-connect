//! Process custody for a staged workflow call on the existing source owner.
//!
//! Durable workflow rows are correlation only. An actual A-to-G native child
//! lineage and both retained originals are checked again during preparation.
//! The admitted G association, grant and ceiling are never replaced here.
use super::*;
use meerkat_authorization::{
    grant_policy::operation_grant_target, grants::ResolvedGrant, policy::LocalPolicyAllowance,
};
use meerkat_authorization_contracts::{grant::GrantLineageRef, work_association::GrantTarget};
use meerkat_core::{
    ToolCallView,
    authorization::{
        OperationAuthorizationError, OperationRefusalKind, OperationRefused,
        PreparedAuthorizationBinding,
    },
};
use std::sync::{
    OnceLock, Weak,
    atomic::{AtomicBool, Ordering},
};
use toolkit_package::{ContentDigest, Id};

const MAX_CALLS: usize = 128;

/// Immutable relationship published before native call preparation. Only the
/// PrivateOriginals workflow owner constructs this from its canonical reads.
pub(crate) struct WorkflowWaiterCustody {
    owner: Arc<ToolkitOriginalOwner>,
    planning: Arc<RetainedToolkitOriginal>,
    waiter: Arc<RetainedToolkitOriginal>,
    selection: Id,
    target: GrantTarget,
    delegation: Vec<GrantLineageRef>,
    deadline_ms: u64,
    calls: Mutex<Vec<Arc<WorkflowCallCustody>>>,
    retired: AtomicBool,
}

/// One call's source custody, not a reusable native authorization result.
/// A plan resolver stages the exact call before native preparation. The policy
/// callback retains the actual native binding on its first matching check.
pub(crate) struct WorkflowCallCustody {
    relationship: Weak<WorkflowWaiterCustody>,
    deadline_ms: u64,
    call_id: String,
    name: String,
    arguments: String,
    arguments_digest: ContentDigest,
    binding: OnceLock<PreparedAuthorizationBinding>,
    entry: Arc<shared_entry::SharedEntry>,
}

impl ToolkitOriginalOwner {
    /// The existing terminal/departure owner selects exact relationships while
    /// holding the same source writer as retain_waiter. This is cleanup only:
    /// the admitted A remains live for its continuation and unrelated work.
    /// The selector cannot create a relationship or carry a cached allowance.
    pub(crate) async fn retire_workflow_membership<F>(
        &self,
        waiter: &InputAuthorityAssociation,
        select: F,
    ) -> Result<(), OriginalWriterError>
    where
        F: FnOnce() -> Result<Vec<Arc<WorkflowWaiterCustody>>, OriginalWriterError>,
    {
        self.reconcile_followup_source(waiter, || async {
            let selected = select()?;
            if selected.iter().any(|item| !std::ptr::eq(self, item.owner.as_ref())
                || item.waiter.association() != waiter)
            { return Err(OriginalWriterError::WrongOwner); }
            // Replay still closes every exact entry, including a prior partial
            // close. Only a newly retired relationship changes policy: empty
            // or already-retired sweeps must not invalidate unrelated work.
            let _publication = if selected.iter().any(|item| !item.retired.load(Ordering::Acquire)) {
                Some(self.publication.begin_owner_change()
                    .map_err(|_| OriginalWriterError::Unavailable)?)
            } else { None };
            for item in selected { item.retire_under_writer()?; }
            Ok(())
        }).await?
    }

    /// Called only by the native workflow launch fence. No reservation exists
    /// before this synchronous entry boundary. The same source writer orders
    /// cancellation against both the actual A check and its entered custody.
    pub(crate) fn enter_workflow_launch(
        &self,
        original: &Arc<RetainedToolkitOriginal>,
    ) -> Result<Arc<shared_entry::SharedEntry>, OriginalWriterError> {
        let _writer = self.mutation.try_lock()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        self.workflow_source_current(original)?;
        let entry = self.retain_shared_entry(original.association(), None)?;
        if let Err(error) = entry.enter() {
            // It has not escaped to native custody. Preserve a failed settle
            // as unavailable; never leave a known-unentered fresh reservation.
            entry.settle()?;
            return Err(error);
        }
        Ok(entry)
    }

    /// Select an actual admitted input's existing controller, never a client
    /// reconstructed from saved selection fields or another member's route.
    pub(crate) fn workflow_controller(
        &self,
        original: &Arc<RetainedToolkitOriginal>,
    ) -> Result<ControllerModelClient, OriginalWriterError> {
        self.workflow_source_current(original)?;
        let originals = self
            .originals
            .lock()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        let _poison = self.publication.poison_on_unwind();
        let held = originals
            .iter()
            .filter_map(OriginalRecord::bound)
            .find(|held| Arc::ptr_eq(&held.retained, original))
            .ok_or(OriginalWriterError::WrongOwner)?;
        let controller = held
            .controller
            .as_ref()
            .ok_or(OriginalWriterError::Unavailable)?;
        if original.association.candidate().controller_model.as_ref()
            != Some(controller.selection())
        {
            return Err(OriginalWriterError::Conflict);
        }
        Ok(controller.clone())
    }

    fn workflow_source_current(
        &self,
        original: &Arc<RetainedToolkitOriginal>,
    ) -> Result<(), OriginalWriterError> {
        let originals = self
            .originals
            .lock()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        let _poison = self.publication.poison_on_unwind();
        let held = originals
            .iter()
            .filter_map(OriginalRecord::bound)
            .find(|held| Arc::ptr_eq(&held.retained, original))
            .ok_or(OriginalWriterError::WrongOwner)?;
        if held.source_custody != Some(SourceCustody::Admitted) {
            return Err(OriginalWriterError::Unavailable);
        }
        match &held.operation {
            OriginalOperationDisposition::Open => Ok(()),
            OriginalOperationDisposition::CancellationPending => {
                Err(OriginalWriterError::Unavailable)
            }
            OriginalOperationDisposition::Cancelled { .. } => {
                Err(OriginalWriterError::OperationCancelled)
            }
        }
    }

    /// Called under retain_followup_source's existing source mutation writer,
    /// after the canonical acquisition/workflow read. The returned relationship
    /// is retained under G before any native plan resolution may use it.
    pub(crate) fn workflow_waiter_custody(
        self: &Arc<Self>,
        planning: Arc<RetainedToolkitOriginal>,
        waiter: Arc<RetainedToolkitOriginal>,
        selection: Id,
        target: GrantTarget,
        delegation: Vec<GrantLineageRef>,
        deadline_ms: u64,
    ) -> Result<Arc<WorkflowWaiterCustody>, OriginalWriterError> {
        self.workflow_source_current(&planning)?;
        self.workflow_source_current(&waiter)?;
        let g = planning.association.candidate();
        let a = waiter.association.candidate();
        if g.requester != a.requester
            || g.ingress_namespace.realm != a.ingress_namespace.realm
            || Arc::ptr_eq(&planning, &waiter)
        {
            return Err(OriginalWriterError::WrongOwner);
        }
        let relationship = Arc::new(WorkflowWaiterCustody {
            owner: self.clone(),
            planning,
            waiter,
            selection,
            target,
            delegation,
            deadline_ms,
            calls: Mutex::new(Vec::new()),
            retired: AtomicBool::new(false),
        });
        relationship.current_grant()?;
        Ok(relationship)
    }
}

impl WorkflowWaiterCustody {
    pub(crate) fn selection(&self) -> &Id {
        &self.selection
    }

    pub(crate) fn same_selection(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
            && Arc::ptr_eq(&self.planning, &other.planning)
            && Arc::ptr_eq(&self.waiter, &other.waiter)
            && self.selection == other.selection
            && self.target == other.target
            && self.delegation == other.delegation
            && self.deadline_ms == other.deadline_ms
    }

    /// Existing workflow departure/expiry owner must call this before awaiting
    /// its durable departure CAS. No replacement or lease expiry reopens it.
    pub(crate) fn retire(&self) -> Result<(), OriginalWriterError> {
        let _writer = self
            .owner
            .mutation
            .try_lock()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        let _publication = self
            .owner
            .publication
            .begin_owner_change()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        self.retire_under_writer()
    }

    // Only this owner module calls this while its mutation and publication
    // writers are held. Never reacquire either writer from the cleanup path.
    fn retire_under_writer(&self) -> Result<(), OriginalWriterError> {
        self.retired.store(true, Ordering::Release);
        let calls = self
            .calls
            .lock()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        let _poison = self.owner.publication.poison_on_unwind();
        for call in calls.iter() {
            call.entry.close()?;
        }
        Ok(())
    }

    /// A native lineage resolved for G, not A's merely live original grant or
    /// a contributor ceiling. Its exact prefix must be A's applicable lineage.
    fn current_grant(&self) -> Result<ResolvedGrant, OriginalWriterError> {
        if self.retired.load(Ordering::Acquire) {
            return Err(OriginalWriterError::OperationDenied);
        }
        self.owner.workflow_source_current(&self.planning)?;
        self.owner.workflow_source_current(&self.waiter)?;
        let now = self
            .owner
            .clock
            .now()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        if now.unix_ms >= self.deadline_ms {
            return Err(OriginalWriterError::OperationDenied);
        }
        let a = self.waiter.association.candidate();
        let g = self.planning.association.candidate();
        let parent = a
            .authority_basis
            .lineage_for(Some(&self.target))
            .ok_or(OriginalWriterError::OperationDenied)?;
        if self.delegation.len() != parent.len() + 1 || !self.delegation.starts_with(parent) {
            return Err(OriginalWriterError::OperationDenied);
        }
        // The native child preserves A's represented subject. Do not silently
        // substitute G's subject, or treat a current A grant as G's authority.
        self.owner
            .grants
            .resolve_lineage(
                &self.delegation,
                &g.logical_executor,
                a.represented_subject.as_ref(),
            )
            .map_err(OriginalWriterError::Grant)
    }

    /// Future workflow plan resolution calls this with the actual call before
    /// native authorization. No async store read occurs here. Publication makes
    /// an earlier prepared stamp stale, even if its G association is unchanged.
    pub(crate) fn stage_call(
        self: &Arc<Self>,
        call: ToolCallView<'_>,
    ) -> Result<Arc<WorkflowCallCustody>, OriginalWriterError> {
        if call.id.is_empty()
            || call.id.len() > 256
            || call.name.is_empty()
            || call.name.len() > 256
            || call.args.get().len() > 1024 * 1024
        {
            return Err(OriginalWriterError::Conflict);
        }
        // Resolve before reserving the publication: native resolution itself
        // observes it. The following reservation and source recheck order the
        // new association with cancellation; final preparation resolves grants.
        self.current_grant()?;
        self.stage_current_call(call)
    }

    // Kept separate so the owner control can exercise retirement after the
    // optimistic grant read but before this exact mutation boundary.
    fn stage_current_call(
        self: &Arc<Self>,
        call: ToolCallView<'_>,
    ) -> Result<Arc<WorkflowCallCustody>, OriginalWriterError> {
        let _writer = self
            .owner
            .mutation
            .try_lock()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        let _publication = self
            .owner
            .publication
            .begin_owner_change()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        if self.retired.load(Ordering::Acquire) {
            return Err(OriginalWriterError::OperationDenied);
        }
        self.owner.workflow_source_current(&self.planning)?;
        self.owner.workflow_source_current(&self.waiter)?;
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| OriginalWriterError::Unavailable)?;
        let _poison = self.owner.publication.poison_on_unwind();
        if let Some(prior) = calls.iter().find(|prior| prior.call_id == call.id) {
            return if prior.name == call.name && prior.arguments == call.args.get() {
                Ok(prior.clone())
            } else {
                Err(OriginalWriterError::Conflict)
            };
        }
        // Do not discard an unsettled/lost call because another waiter arrived.
        calls.retain(|call| !call.entry.settled());
        if calls.len() >= MAX_CALLS {
            return Err(OriginalWriterError::Unavailable);
        }
        let entry = self
            .owner
            .retain_shared_entry(&self.waiter.association, None)?;
        let staged = Arc::new(WorkflowCallCustody {
            relationship: Arc::downgrade(self),
            deadline_ms: self.deadline_ms,
            call_id: call.id.to_owned(),
            name: call.name.to_owned(),
            arguments: call.args.get().to_owned(),
            arguments_digest: ContentDigest::of_bytes(call.args.get().as_bytes()),
            binding: OnceLock::new(),
            entry,
        });
        calls.push(staged.clone());
        Ok(staged)
    }

    pub(crate) fn prepared_call(
        &self,
        association: &InputAuthorityAssociation,
        binding: &PreparedAuthorizationBinding,
    ) -> Result<Option<Arc<WorkflowCallCustody>>, OriginalWriterError> {
        if &self.planning.association != association {
            return Err(OriginalWriterError::WrongOwner);
        }
        let meerkat_core::authorization::AuthorizationOperation::Tool(facts) =
            &binding.facts().operation
        else {
            return Ok(None);
        };
        let selected = {
            let calls = self
                .calls
                .lock()
                .map_err(|_| OriginalWriterError::Unavailable)?;
            let _poison = self.owner.publication.poison_on_unwind();
            calls
                .iter()
                .find(|call| call.call_id == facts.call_id.as_ref())
                .cloned()
        };
        let Some(call) = selected else {
            return Ok(None);
        };
        if call.name != facts.name.as_str()
            || call.arguments != facts.arguments.get()
            || call.arguments_digest != ContentDigest::of_bytes(facts.arguments.get().as_bytes())
            || operation_grant_target(binding).map_err(|_| OriginalWriterError::OperationDenied)?
                != Some(self.target.clone())
        {
            return Err(OriginalWriterError::Conflict);
        }
        // This stores identity only. All permission-bearing relationship facts
        // were already published before preparation; no allowance is cached.
        let retained = call.binding.get_or_init(|| binding.clone());
        if !retained.same_operation(binding) {
            return Err(OriginalWriterError::Conflict);
        }
        call.current()?;
        Ok(Some(call))
    }
}

impl WorkflowCallCustody {
    pub(crate) fn current(&self) -> Result<ResolvedGrant, OriginalWriterError> {
        if self.entry.settled() {
            return Err(OriginalWriterError::OperationDenied);
        }
        self.relationship
            .upgrade()
            .ok_or(OriginalWriterError::Unavailable)?
            .current_grant()
    }
    /// Contribute A's actual applicable lineage to G's current operation.
    /// This is a policy input only; Core still checks G and its admitted ceiling.
    pub(crate) fn narrow_allowance(
        &self,
        allowance: &mut LocalPolicyAllowance,
        now_ms: u64,
    ) -> Result<(), OperationAuthorizationError> {
        let delegation = self.current().map_err(|error| match error {
            OriginalWriterError::Unavailable => OperationAuthorizationError::Unavailable,
            _ => OperationRefused::new(OperationRefusalKind::Denied).into(),
        })?;
        narrow_delegation_allowance(&delegation, self.deadline_ms, allowance, now_ms)
    }

    /// For the later native final-check closure only. The native checked entry
    /// must still follow this gate and recheck G under the common publication.
    /// This method by itself is not an authorized effect-entry operation.
    pub(crate) fn enter_source_gate(&self) -> Result<(), OriginalWriterError> {
        if self.binding.get().is_none() {
            return Err(OriginalWriterError::Unavailable);
        }
        self.current()?;
        self.entry.enter()
    }
    pub(crate) fn settle(&self) -> Result<(), OriginalWriterError> {
        self.entry.settle()
    }
}

fn narrow_delegation_allowance(
    delegation: &ResolvedGrant,
    deadline_ms: u64,
    allowance: &mut LocalPolicyAllowance,
    now_ms: u64,
) -> Result<(), OperationAuthorizationError> {
    use meerkat_authorization::mcp_installation::{
        MCP_CONNECTOR_FEATURE, McpConnectorBound, lineage_connector_bound,
    };
    for values in &allowance.operation_values {
        if values.action.feature == MCP_CONNECTOR_FEATURE {
            // Core checks G's connector record separately. G's approval cannot
            // fill missing evidence on A's independently delegated lineage.
            match lineage_connector_bound(
                delegation.lineage_restrictions(),
                delegation.restrictions(),
                &values.action,
                &values.resource_domain,
            ) {
                McpConnectorBound::Approved => {}
                McpConnectorBound::Other => {
                    return Err(OperationRefused::new(OperationRefusalKind::Denied).into());
                }
                McpConnectorBound::Unrecorded => {
                    return Err(OperationAuthorizationError::Unavailable);
                }
            }
        }
    }
    // The actual G tuple is checked by Core against all conjoined dimensions,
    // including A's audience restriction. Source audience equality is not a
    // prerequisite and cannot replace that operation-applicable bound check.
    allowance.restrictions = allowance.restrictions.conjoin(delegation.restrictions());
    allowance.expires_at_ms = allowance
        .expires_at_ms
        .min(delegation.expires_at_ms())
        .min(deadline_ms);
    if allowance.expires_at_ms <= now_ms {
        return Err(OperationRefused::new(OperationRefusalKind::Denied).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
