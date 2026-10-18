//! Bind dormant workflow records to the existing live source/controller owner.
//!
//! These methods are internal entry points for the next workflow launch and
//! plan-resolution adapters. They do not spawn G, dispatch an input, acknowledge
//! an outbox effect, or substitute stored membership for native authorization.
use super::*;
use crate::original_ingress::workflow_custody::{WorkflowCallCustody, WorkflowWaiterCustody};
use meerkat_authorization_contracts::work_association::{GrantTarget, InputAuthorityAssociation};
use meerkat_core::{
    ControllerModelClient, MobMemberBinding, ToolCallView,
    authorization::PreparedAuthorizationBinding,
};
use meerkat_toolkit::{
    request::RequestContext,
    setup::{
        SetupAccess, SetupScope, SetupStore, SetupWorkflowRef, SetupWorkflowSnapshot,
        SetupWorkflowWaiter,
    },
};
use toolkit_package::ContentDigest;
use std::sync::atomic::{AtomicBool, Ordering};

mod member;
pub use member::InstalledWorkflowMember;
mod launch;
#[cfg(test)]
pub(crate) use launch::OwnedTransferCommit;
pub use launch::{InstalledWorkflowPlanning, InstalledWorkflowContextTransfer, InstalledWorkflowContext, WorkflowContextObservation, WorkflowDeliveryObservation};
pub(crate) use launch::WorkflowTransferObservation;
pub(crate) use launch::WorkflowLaunchObservation;
pub(crate) use launch::WorkflowTerminalRecovery;
pub(crate) use launch::InvocationPlanning;
pub(in crate::private_originals) use launch::PreparedWorkflowLaunch;

/// Process-local attachment under the actual G source, never reconstructed
/// from workflow terms. It retains the controller supplied by native admission.
pub(crate) struct HeldSetupWorkflow {
    source: Weak<PrivateOriginals>,
    planning: Arc<RetainedToolkitOriginal>,
    reference: SetupWorkflowRef,
    member: MobMemberBinding,
    session: meerkat_core::SessionId,
    controller: ControllerModelClient,
    accepted: AtomicBool,
    deadline_ms: u64,
    waiters: Mutex<Vec<Arc<HeldWorkflowWaiter>>>,
}

/// Canonical inline request bytes remain owned here until the later governed
/// disclosure binder can carry them through its actual final-admission fence.
/// There is deliberately no public payload accessor or delivery receipt.
pub(crate) struct HeldWorkflowWaiter {
    workflow: Weak<HeldSetupWorkflow>,
    membership: SetupWorkflowWaiter,
    request: String,
    request_digest: ContentDigest,
    authority: Arc<WorkflowWaiterCustody>,
}

impl PrivateOriginals {
    fn workflow_store(&self) -> Result<SetupStore<'_>, PrivateOriginalError> {
        Ok(SetupStore::new(
            self.store.as_ref(),
            SetupScope::new(
                Id::new(self.scope.realm.clone()).map_err(|_| PrivateOriginalError::Conflict)?,
                Id::new(self.scope.owner.clone()).map_err(|_| PrivateOriginalError::Conflict)?,
            ),
        )
        .map_err(|_| PrivateOriginalError::Unavailable)?)
    }

    /// Attach an already-admitted G using its retained native context/member.
    /// The initial pre-admission binder cannot satisfy this async method, and
    /// synchronous accepted settlement cannot await its store read. First-lead
    /// launch must stage the canonical data before dispatch and attach it from
    /// exact accepted custody without a later store read. No JSON constructor
    /// accepts these owner facts.
    pub(crate) async fn bind_setup_workflow(
        self: &Arc<Self>,
        reference: &SetupWorkflowRef,
        planning: &PrivateOriginalRef,
        context: &meerkat_mobkit::identity_first::GovernedBindContext,
        member: &MobMemberBinding,
    ) -> Result<Arc<HeldSetupWorkflow>, PrivateOriginalError> {
        let snapshot = self
            .workflow_store()?
            .load_setup_workflow(reference)
            .await
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let terms = snapshot.terms();
        if snapshot.active_waiters() == 0
            || terms.planning_source != self.key(planning)?
            || &terms.lead != member
        {
            return Err(PrivateOriginalError::Denied);
        }
        let held = self
            .retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .iter()
            .find(|held| &held.reference == planning)
            .cloned()
            .ok_or(PrivateOriginalError::Unavailable)?;
        let claims = held.original.association().candidate();
        if claims.requester != terms.requester
            || claims.ingress_namespace.realm != terms.realm
            || claims.target.context.as_str() != context.session_id.to_string()
            || claims.target.logical_runtime.as_str()
                != meerkat_runtime::LogicalRuntimeId::for_session(&context.session_id).to_string()
            || claims.controller_model.as_ref() != Some(context.controller.selection())
        {
            return Err(PrivateOriginalError::Denied);
        }
        let controller = self
            .owner
            .workflow_controller(&held.original)
            .map_err(custody_error)?;
        let candidate = Arc::new(HeldSetupWorkflow {
            source: Arc::downgrade(self),
            planning: held.original.clone(),
            reference: reference.clone(),
            member: member.clone(),
            session: context.session_id.clone(),
            controller,
            accepted: AtomicBool::new(true),
            deadline_ms: terms.deadline_ms,
            waiters: Mutex::new(Vec::new()),
        });
        // This only attaches process custody after the durable read. It cannot
        // acknowledge launch or make a saved G reference into native admission.
        let publication = self.owner.publication();
        let _publication = publication
            .begin_owner_change()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let retained = held.setup_workflow.get_or_init(|| candidate);
        if retained.reference != *reference
            || retained.member != *member
            || retained.session != context.session_id
            || !Arc::ptr_eq(&retained.planning, &held.original)
            || retained.controller.selection() != context.controller.selection()
        {
            return Err(PrivateOriginalError::Conflict);
        }
        Ok(retained.clone())
    }

    /// Synchronous native policy projection only. Durable reads/relationship
    /// selection finished before native preparation. No policy answer is cached.
    pub(crate) fn workflow_call_for_policy(
        &self,
        association: &InputAuthorityAssociation,
        binding: &PreparedAuthorizationBinding,
    ) -> Result<Option<Arc<WorkflowCallCustody>>, PrivateOriginalError> {
        let held = self
            .retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .iter()
            .find(|held| held.original.association() == association)
            .cloned();
        let Some(workflow) = held.as_ref().and_then(|held| held.setup_workflow.get()) else {
            return Ok(None);
        };
        // Native may prepare work before accepted settlement runs. The
        // pending attachment is already present, so it cannot fall through
        // to singleton operation policy during that interval.
        workflow.current_source()?;
        let waiters = workflow
            .waiters
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let publication = self.owner.publication();
        let _poison = publication.poison_on_unwind();
        let mut found = None;
        for waiter in waiters.iter() {
            if let Some(call) = waiter
                .authority
                .prepared_call(association, binding)
                .map_err(custody_error)?
            {
                if found.is_some() {
                    return Err(PrivateOriginalError::Conflict);
                }
                found = Some(call);
            }
        }
        // Once G owns a workflow, an unstaged MCP call cannot silently take
        // the ordinary singleton path. Controller/catalog planning is unchanged.
        if found.is_none()
            && matches!(
                meerkat_authorization::grant_policy::operation_grant_target(binding)
                    .map_err(|_| PrivateOriginalError::Denied)?,
                Some(GrantTarget::McpServer { .. })
            )
        {
            return Err(PrivateOriginalError::Denied);
        }
        Ok(found)
    }
}

impl HeldSetupWorkflow {
    fn current_source(&self) -> Result<Arc<PrivateOriginals>, PrivateOriginalError> {
        if !self.accepted.load(Ordering::Acquire) {
            return Err(PrivateOriginalError::Unavailable);
        }
        let source = self
            .source
            .upgrade()
            .ok_or(PrivateOriginalError::Unavailable)?;
        if source
            .owner
            .clock()
            .now()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .unix_ms
            >= self.deadline_ms
        {
            return Err(PrivateOriginalError::Denied);
        }
        source
            .owner
            .workflow_controller(&self.planning)
            .map_err(custody_error)?;
        Ok(source)
    }

    /// The current host invocation supplies SetupAccess. Its canonical A read
    /// and reference checks happen outside every synchronous publication read.
    /// Actual disclosure/native dispatch are intentionally not performed here.
    pub(crate) async fn retain_waiter(
        self: &Arc<Self>,
        membership: &SetupWorkflowWaiter,
        original: &PrivateOriginalRef,
        access: SetupAccess<'_>,
        target: GrantTarget,
        delegation: Vec<meerkat_authorization_contracts::grant::GrantLineageRef>,
    ) -> Result<Arc<HeldWorkflowWaiter>, PrivateOriginalError> {
        let source = self.current_source()?;
        if membership.workflow() != &self.reference
            || membership.source() != &source.key(original)?
        {
            return Err(PrivateOriginalError::Denied);
        }
        let held = source
            .retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .iter()
            .find(|held| &held.reference == original)
            .cloned()
            .ok_or(PrivateOriginalError::Unavailable)?;
        source
            .owner
            .retain_followup_source(held.original.association(), || async {
                let setup = source
                    .workflow_store()
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                let workflow = setup
                    .load_setup_workflow(&self.reference)
                    .await
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                require_active(&workflow, membership)?;
                let operation = Id::new(membership.acquisition().id.clone())
                    .map_err(|_| OriginalWriterError::Conflict)?;
                let acquisition = setup
                    .load(&operation, access.evidence, access.context, access.references)
                    .await
                    .map_err(|error| match error {
                        meerkat_toolkit::setup::SetupError::Store(_) => OriginalWriterError::Unavailable,
                        meerkat_toolkit::setup::SetupError::Request(_)
                        | meerkat_toolkit::setup::SetupError::Denied => OriginalWriterError::OperationDenied,
                        _ => OriginalWriterError::Conflict,
                    })?;
                if acquisition.key() != membership.acquisition()
                    || acquisition.request().evidence().association() != held.original.association()
                    || setup
                        .workflow_waiter(
                            workflow.terms(),
                            &acquisition,
                            membership.source().clone(),
                        )
                        .map_err(|_| OriginalWriterError::Conflict)?
                        != *membership
                {
                    return Err(OriginalWriterError::WrongOwner);
                }
                if !matches!(
                    acquisition.state().lifecycle_phase,
                    toolkit_catalog::AcquisitionPhase::Investigating
                        | toolkit_catalog::AcquisitionPhase::Preparing
                ) {
                    return Err(OriginalWriterError::OperationDenied);
                }
                acquisition
                    .request()
                    .revalidate(access.evidence, access.context, access.references)
                    .map_err(|_| OriginalWriterError::OperationDenied)?;
                // The current installed owner cannot resolve arbitrary references.
                // Do not copy reference labels or claim they disclose their bytes.
                if acquisition
                    .request()
                    .request()
                    .user_context
                    .iter()
                    .any(|value| matches!(value, RequestContext::Reference(_)))
                {
                    return Err(OriginalWriterError::UnsupportedMandate);
                }
                let request = String::from_utf8(
                    canonical_json(acquisition.request().request())
                        .map_err(|_| OriginalWriterError::Conflict)?,
                )
                .map_err(|_| OriginalWriterError::Conflict)?;
                let request_digest = ContentDigest::of_bytes(request.as_bytes());
                if request_digest != membership.input().content_digest {
                    return Err(OriginalWriterError::Conflict);
                }
                let authority = source.owner.workflow_waiter_custody(
                    self.planning.clone(),
                    held.original.clone(),
                    Id::new(membership.acquisition().id.clone())
                        .map_err(|_| OriginalWriterError::Conflict)?,
                    target,
                    delegation,
                    membership.deadline_ms(),
                )?;
                // A's source writer still excludes its cancellation publication.
                // This mutation invalidates preparations that predate the binding.
                let publication = source.owner.publication();
                let _publication = publication
                    .begin_owner_change()
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                let mut waiters = self
                    .waiters
                    .lock()
                    .map_err(|_| OriginalWriterError::Unavailable)?;
                let _poison = publication.poison_on_unwind();
                if let Some(prior) = waiters
                    .iter()
                    .find(|waiter| waiter.membership == *membership)
                {
                    return if prior.request == request
                        && prior.request_digest == request_digest
                        && prior.authority.same_selection(&authority)
                    {
                        Ok(prior.clone())
                    } else {
                        Err(OriginalWriterError::Conflict)
                    };
                }
                if waiters.len() >= 128 {
                    return Err(OriginalWriterError::Unavailable);
                }
                let waiter = Arc::new(HeldWorkflowWaiter {
                    workflow: Arc::downgrade(self),
                    membership: membership.clone(),
                    request,
                    request_digest,
                    authority,
                });
                waiters.push(waiter.clone());
                Ok(waiter)
            })
            .await
            .map_err(custody_error)
    }
}

impl HeldWorkflowWaiter {
    /// Next caller: the same workflow departure/expiry owner, before it awaits
    /// the durable departure CAS. This never acknowledges that durable result.
    pub(crate) fn retire(&self) -> Result<(), PrivateOriginalError> {
        self.authority.retire().map_err(custody_error)
    }

    /// Next caller: the workflow-aware native plan resolver, before Core
    /// creates/prepares its real binding. Selection IDs are only lookup keys.
    pub(crate) fn stage_call(
        &self,
        call: ToolCallView<'_>,
    ) -> Result<Arc<WorkflowCallCustody>, PrivateOriginalError> {
        let workflow = self
            .workflow
            .upgrade()
            .ok_or(PrivateOriginalError::Unavailable)?;
        workflow.current_source()?;
        self.authority.stage_call(call).map_err(custody_error)
    }
}

fn require_active(
    workflow: &SetupWorkflowSnapshot,
    waiter: &SetupWorkflowWaiter,
) -> Result<(), OriginalWriterError> {
    // Sealing closes admission of new members. Exact active members keep
    // their independently authorized continuation and recovery path.
    if workflow
            .departed(waiter)
            .map_err(|_| OriginalWriterError::Conflict)?
    {
        return Err(OriginalWriterError::OperationDenied);
    }
    Ok(())
}
fn custody_error(error: OriginalWriterError) -> PrivateOriginalError {
    match error {
        OriginalWriterError::Unavailable => PrivateOriginalError::Unavailable,
        OriginalWriterError::Conflict => PrivateOriginalError::Conflict,
        _ => PrivateOriginalError::Denied,
    }
}
