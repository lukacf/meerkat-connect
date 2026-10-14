//! The existing identity runtime's real setup-helper preparation and input path.
//! WorkGraph admission precedes every call here. No frontend event is fabricated.

use super::*;
use crate::original_ingress::{
    PendingToolkitOriginal,
    helper_originals::{
        AdmittedHelperWork, HelperAdmissionSelection, HelperNativeBinding, HelperOperation,
        RetainedHelperSource,
    },
};
use async_trait::async_trait;
use meerkat_authorization_contracts::{
    constraints::ExecutionRestrictions, grant::GrantLineageRef, work_association::{NativeWorkTarget, WorkAuthorityBasis},
};
use meerkat_core::{ControllerModelClient, SessionId, ToolDispatchContext, lifecycle::InputId, types::ToolCallView};
use meerkat_mobkit::identity_first::{
    BoundGovernedInput, GovernedAdmission, GovernedBindContext, GovernedInputBinder,
    GovernedInputError, GovernedSettlement, IdentityRuntimeError, TurnTracking,
};
use meerkat_runtime::{Input, PromptInput};
use meerkat_workgraph::{CreateWorkItemRequest, WorkAdmissionKey, WorkGraphService};
use toolkit_package::ContentDigest;

mod controller;
mod entry;

/// An actual retained native controller/registration observation. This is not
/// a grant, source custody or proof that the setup helper was admitted.
pub(crate) struct PreparedHelperController {
    source: Weak<PrivateOriginals>,
    admitted: Arc<AdmittedHelperWork>,
    session_id: SessionId,
    target: NativeWorkTarget,
    controller: ControllerModelClient,
}

impl PreparedHelperController {
    pub(crate) fn controller(&self) -> &ControllerModelClient {
        &self.controller
    }
    pub(crate) fn admitted(&self) -> &Arc<AdmittedHelperWork> {
        &self.admitted
    }
    pub(crate) fn target(&self) -> &NativeWorkTarget {
        &self.target
    }
}

/// Kept by the existing source adapter when native cannot settle admission.
/// Its guard owns only source custody. Native remains the input/turn owner.
pub(crate) struct HeldSetupHelper {
    source: RetainedHelperSource,
    unresolved: Mutex<Vec<Box<dyn GovernedSettlement>>>,
}

impl HeldSetupHelper {
    pub(crate) fn original(&self) -> &Arc<RetainedToolkitOriginal> {
        &self.source.original
    }
    pub(crate) fn source_record(&self) -> &Arc<StoredRecord> {
        &self.source.source_record
    }
}

impl PrivateOriginals {
    #[cfg(test)]
    pub(crate) fn canonical_store_for_policy_fixture(&self) -> &dyn ToolkitStore {
        self.store.as_ref()
    }

    /// Retain an actual canonical helper source for policy-component controls.
    /// This neither promotes input custody nor installs a permissive owner.
    #[cfg(test)]
    pub(crate) fn retain_helper_policy_fixture(&self, source: RetainedHelperSource) {
        source.policy_source().unwrap();
        self.helper_sources.lock().unwrap().push(Arc::new(HeldSetupHelper {
            source, unresolved: Mutex::new(Vec::new()),
        }));
    }

    /// Exact immutable source facts from a handle this source owner retained.
    /// The native input and grant owners still decide current custody/permission.
    /// No storage read or native lock is taken under the caller's publication.
    pub(crate) fn helper_policy_source(
        &self,
        association: &meerkat_authorization_contracts::work_association::InputAuthorityAssociation,
    ) -> Result<Option<crate::original_ingress::helper_originals::HelperPolicySource>, PrivateOriginalError> {
        let held = self.helper_sources.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
        let mut matches = held.iter().filter(|source| source.original().association() == association);
        let Some(source) = matches.next() else { return Ok(None); };
        if matches.next().is_some() { return Err(PrivateOriginalError::Conflict); }
        source.source.policy_source().map(Some).map_err(helper_error)
    }

    /// Selected application's private settlement custody only. The caller is
    /// the installed acquisition owner using this same source/store scope;
    /// it has already validated the immutable canonical effect/input. This
    /// guard is not a native WorkGraph read grant or permission to retry.
    /// The callback moves an immutable private projection and performs no I/O.
    pub(crate) fn with_private_setup_recovery(
        &self,
        realm: &str,
        source_owner: &str,
        disclose: Box<dyn FnOnce() + Send + '_>,
    ) -> Result<(), PrivateOriginalError> {
        if self.scope.realm != realm || self.scope.owner != source_owner {
            return Err(PrivateOriginalError::Denied);
        }
        let lifetime = self
            .host_lifetime
            .get()
            .and_then(Weak::upgrade)
            .ok_or(PrivateOriginalError::Unavailable)?;
        lifetime
            .with_current_setup(|| {
                disclose();
                Ok(())
            })
            .map_err(|error| match error {
                meerkat_toolkit::host_lifetime::control::HostLifetimeError::Unavailable => {
                    PrivateOriginalError::Unavailable
                }
                _ => PrivateOriginalError::Denied,
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn admit_setup_helper(
        self: &Arc<Self>,
        call: ToolCallView<'_>,
        context: &ToolDispatchContext,
        service: &WorkGraphService,
        key: WorkAdmissionKey,
        request: CreateWorkItemRequest,
        operation: HelperOperation,
        selection: HelperAdmissionSelection,
    ) -> Result<Arc<AdmittedHelperWork>, PrivateOriginalError> {
        let original = self.acquisition_original(context).await?;
        self.require_helper_selection(&selection)?;
        self.owner
            .admit_fenced_helper(
                call,
                context,
                self.store.as_ref(),
                &self.scope,
                service,
                key,
                request,
                operation,
                original.setup_origin(),
                &original.original,
                &original.contributors,
                &original.own_originals,
                selection,
            )
            .await
            .map(Arc::new)
            .map_err(helper_error)
    }

    #[allow(clippy::too_many_arguments)]
    /// Current M1 replay disclosure for a live invocation only. This is not
    /// independent host-private recovery after originating work is cancelled.
    pub(crate) async fn observe_setup_helper_for_live_replay(
        self: &Arc<Self>,
        call: ToolCallView<'_>,
        context: &ToolDispatchContext,
        service: &WorkGraphService,
        key: WorkAdmissionKey,
        request: CreateWorkItemRequest,
        operation: HelperOperation,
        selection: HelperAdmissionSelection,
    ) -> Result<Option<Arc<AdmittedHelperWork>>, PrivateOriginalError> {
        let original = self.acquisition_original(context).await?;
        self.require_helper_selection(&selection)?;
        self.owner
            .observe_fenced_helper(
                call,
                context,
                self.store.as_ref(),
                &self.scope,
                service,
                key,
                request,
                operation,
                original.setup_origin(),
                &original.original,
                &original.contributors,
                &original.own_originals,
                selection,
            )
            .await
            .map(|observed| observed.map(Arc::new))
            .map_err(helper_error)
    }

    fn require_helper_selection(
        &self,
        selection: &HelperAdmissionSelection,
    ) -> Result<(), PrivateOriginalError> {
        let lifetime = self
            .host_lifetime
            .get()
            .and_then(Weak::upgrade)
            .ok_or(PrivateOriginalError::Unavailable)?;
        lifetime
            .validate_current_selection()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let policy = lifetime.selected_policy();
        let native = policy
            .native_host
            .as_ref()
            .ok_or(PrivateOriginalError::Unavailable)?;
        if self.scope.realm != native.realm.to_string()
            || self.scope.owner != policy.deployment.to_string()
            || self.owner.ingress_domain() != &native.ingress_domain
            || selection.grant_caller != native.grant_administrator
            || selection.helper.member != selection.member.member
            || !native
                .members
                .iter()
                .any(|member| member == &selection.member)
        {
            return Err(PrivateOriginalError::Denied);
        }
        Ok(())
    }

    /// The real native identity lease supplies its client and session. The
    /// binder returns the typed Bind branch before submitting any native input.
    /// This is called only after fenced work admission, so a cold helper is
    /// never created before acquisition coalescing has selected its one item.
    pub(crate) async fn prepare_setup_helper(
        self: &Arc<Self>,
        admitted: Arc<AdmittedHelperWork>,
        content: String,
        source_deadline: tokio::time::Instant,
    ) -> Result<PreparedHelperController, PrivateOriginalError> {
        // The native acceptance callback is independent of this tool's turn.
        // Wait before any Meta identity call, with no mutation/publication
        // guard held. Each observation performs the same strict contributor
        // check; the native binder and publication paths still recheck below.
        self.owner
            .wait_admitted_helper(&admitted, source_deadline)
            .await
            .map_err(helper_error)?;
        self.require_helper_selection(admitted.selection())?;
        if ContentDigest::of_bytes(content.as_bytes()) != admitted.operation().input_digest {
            return Err(PrivateOriginalError::Conflict);
        }
        let runtime = self
            .identity_runtime
            .get()
            .and_then(|runtime| runtime.upgrade())
            .ok_or(PrivateOriginalError::Unavailable)?;
        let alias = admitted.selection().member.member.member.clone();
        let identity = runtime
            .owned_identity_for_member_alias(&alias)
            .await
            .ok_or(PrivateOriginalError::Unavailable)?;
        let binder = Arc::new(PrepareHelperBinder {
            source: Arc::downgrade(self),
            admitted,
            captured: Mutex::new(None),
        });
        let outcome = runtime
            .dispatch_governed_with_turn_ticket(
                &identity,
                Some(&alias),
                Input::Prompt(PromptInput::new(content, None)),
                binder.clone(),
            )
            .await;
        if !matches!(
            outcome,
            Err(IdentityRuntimeError::GovernedInput(
                GovernedInputError::Bind(_)
            ))
        ) {
            return Err(PrivateOriginalError::Unavailable);
        }
        let captured = binder
            .captured
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .take();
        captured.ok_or(PrivateOriginalError::Unavailable)
    }

    /// Recover only a previously retained source for this exact work and
    /// actual native controller/session. A missing source stays missing; this
    /// method issues no grant and cannot replace the saved destination.
    pub(crate) async fn recover_setup_helper_source(
        self: &Arc<Self>,
        prepared: &PreparedHelperController,
    ) -> Result<Option<Arc<HeldSetupHelper>>, PrivateOriginalError> {
        if !prepared
            .source
            .upgrade()
            .is_some_and(|source| Arc::ptr_eq(&source, self))
        {
            return Err(PrivateOriginalError::Denied);
        }
        self.require_helper_selection(prepared.admitted.selection())?;
        let Some(binding) = self
            .owner
            .observe_helper_binding(self.store.as_ref(), &prepared.admitted)
            .await
            .map_err(helper_error)?
        else {
            return Ok(None);
        };
        if binding.target != prepared.target
            || &binding.controller_model != prepared.controller.selection()
        {
            return Err(PrivateOriginalError::Conflict);
        }
        self.retain_setup_helper_source(prepared, binding.controller_grant_lineage, binding.authority_basis)
            .await
            .map(Some)
    }

    /// The actual native child issuer supplies this lineage. This method never
    /// issues a grant or treats its configured parent as a runnable child.
    /// Resolve the issued path with the real owner, then retain the exact source.
    pub(crate) async fn retain_setup_helper_source(
        self: &Arc<Self>,
        prepared: &PreparedHelperController,
        issued_controller_lineage: Vec<GrantLineageRef>,
        operation_basis: WorkAuthorityBasis,
    ) -> Result<Arc<HeldSetupHelper>, PrivateOriginalError> {
        if !prepared
            .source
            .upgrade()
            .is_some_and(|source| Arc::ptr_eq(&source, self))
        {
            return Err(PrivateOriginalError::Denied);
        }
        self.owner
            .check_admitted_helper(&prepared.admitted)
            .map_err(helper_error)?;
        self.require_helper_selection(prepared.admitted.selection())?;
        let selected = &prepared.admitted.selection().helper;
        if issued_controller_lineage.len() != selected.controller_parent.len() + 1
            || !issued_controller_lineage.starts_with(&selected.controller_parent)
        {
            return Err(PrivateOriginalError::Denied);
        }
        let controller_ceiling = {
            let grants = self.owner.grants();
            let resolved = grants
                .resolve_controller_lineage(
                    &issued_controller_lineage,
                    &selected.logical_executor,
                    selected.represented_subject.as_ref(),
                )
                .map_err(|_| PrivateOriginalError::Denied)?;
            resolved
                .check_current()
                .map_err(|_| PrivateOriginalError::Unavailable)?;
            resolved.restrictions().clone()
        };
        let binding = HelperNativeBinding {
            ingress_actor: selected.ingress_actor.clone(),
            logical_executor: selected.logical_executor.clone(),
            represented_subject: selected.represented_subject.clone(),
            target: prepared.target.clone(),
            authority_basis: operation_basis,
            controller_grant_lineage: issued_controller_lineage,
            controller_model: prepared.controller.selection().clone(),
            controller_ceiling,
            admitted_ceiling: ExecutionRestrictions::unrestricted(),
        };
        let source = self
            .owner
            .bind_admitted_helper(self.store.as_ref(), &prepared.admitted, binding)
            .await
            .map_err(helper_error)?;
        let mut held = self
            .helper_sources
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        if let Some(prior) = held
            .iter()
            .find(|prior| prior.source.source_record.key == source.source_record.key)
        {
            if prior.source.source_record != source.source_record
                || !Arc::ptr_eq(&prior.source.original, &source.original)
            {
                return Err(PrivateOriginalError::Conflict);
            }
            return Ok(prior.clone());
        }
        let source = Arc::new(HeldSetupHelper {
            source,
            unresolved: Mutex::new(Vec::new()),
        });
        held.push(source.clone());
        Ok(source)
    }

    /// Export only exact source history for the existing preparation owner.
    /// Publication still requires its acquisition/effect claim and native
    /// operation admission; this is not a new permission-bearing token.
    pub(crate) async fn setup_helper_publication_source(
        self: &Arc<Self>,
        prepared: &PreparedHelperController,
        held: &Arc<HeldSetupHelper>,
        service: &WorkGraphService,
    ) -> Result<meerkat_toolkit::setup::NativeHelperSource, PrivateOriginalError> {
        if !prepared
            .source
            .upgrade()
            .is_some_and(|source| Arc::ptr_eq(&source, self))
            || !self
                .helper_sources
                .lock()
                .map_err(|_| PrivateOriginalError::Unavailable)?
                .iter()
                .any(|entry| Arc::ptr_eq(entry, held))
            || held.source.original.association().candidate().target != prepared.target
        {
            return Err(PrivateOriginalError::Denied);
        }
        self.require_helper_selection(prepared.admitted.selection())?;
        self.owner
            .helper_publication_source(
                self.store.as_ref(),
                service,
                &prepared.admitted,
                &held.source,
            )
            .await
            .map_err(helper_error)
    }

    /// Re-open exactly the contributor rows selected by the native invocation.
    /// The preparation owner uses their versions in its same-store conditional
    /// write. No catalog scan, source copy or new authority is constructed.
    pub(crate) async fn setup_helper_contributor_conditions(
        self: &Arc<Self>,
        admitted: &AdmittedHelperWork,
    ) -> Result<Vec<toolkit_store::RecordCondition>, PrivateOriginalError> {
        self.owner
            .check_admitted_helper(admitted)
            .map_err(helper_error)?;
        self.require_helper_selection(admitted.selection())?;
        let sources = {
            let retained = self
                .retained
                .lock()
                .map_err(|_| PrivateOriginalError::Unavailable)?;
            let mut sources = Vec::with_capacity(admitted.contributors().len());
            for original in admitted.contributors() {
                let mut matches = retained
                    .iter()
                    .filter(|held| Arc::ptr_eq(&held.original, original));
                let held = matches.next().ok_or(PrivateOriginalError::Unavailable)?;
                if matches.next().is_some() {
                    return Err(PrivateOriginalError::Conflict);
                }
                sources.push((held.reference.clone(), original.clone()));
            }
            sources
        };
        let mut conditions = Vec::with_capacity(sources.len());
        for (reference, original) in sources {
            let saved = self
                .store
                .get(&self.key(&reference)?)
                .await
                .map_err(store_error)?
                .ok_or(PrivateOriginalError::Unavailable)?;
            let source = self.decode_record(&saved, &reference)?;
            if source.operation_cancelled {
                return Err(PrivateOriginalError::Denied);
            }
            if source.final_association.as_ref() != Some(original.association()) {
                return Err(PrivateOriginalError::Conflict);
            }
            conditions.push(toolkit_store::RecordCondition {
                key: saved.key,
                revision: saved.revision,
                content_digest: saved.content_digest,
                claim: None,
                dispatch_claim: None,
            });
        }
        self.owner
            .check_admitted_helper(admitted)
            .map_err(helper_error)?;
        Ok(conditions)
    }

    /// Submit the exact source under the same existing identity owner. Real
    /// native acceptance/dedup/uncertainty controls the custody settlement.
    pub(crate) async fn submit_setup_helper(
        self: &Arc<Self>,
        prepared: &PreparedHelperController,
        held: Arc<HeldSetupHelper>,
        content: String,
    ) -> Result<PrivateOriginalSubmission, PrivateOriginalError> {
        if !prepared
            .source
            .upgrade()
            .is_some_and(|source| Arc::ptr_eq(&source, self))
            || ContentDigest::of_bytes(content.as_bytes())
                != prepared.admitted.operation().input_digest
            || !held.source.matches_admission(&prepared.admitted)
            || held.source.original.association().candidate().target != prepared.target
            || !self
                .helper_sources
                .lock()
                .map_err(|_| PrivateOriginalError::Unavailable)?
                .iter()
                .any(|entry| Arc::ptr_eq(entry, &held))
        {
            return Err(PrivateOriginalError::Denied);
        }
        self.owner
            .check_admitted_helper(&prepared.admitted)
            .map_err(helper_error)?;
        self.require_helper_selection(prepared.admitted.selection())?;
        // Capture every actual contributing login before later identity/member
        // awaits. The same handles order final native entry against retirement.
        let entry_fence = entry::for_logins(self.helper_controller_logins(&prepared.admitted)?);
        let runtime = self
            .identity_runtime
            .get()
            .and_then(|runtime| runtime.upgrade())
            .ok_or(PrivateOriginalError::Unavailable)?;
        let alias = &prepared.admitted.selection().member.member.member;
        let identity = runtime
            .owned_identity_for_member_alias(alias)
            .await
            .ok_or(PrivateOriginalError::Unavailable)?;
        let binder = Arc::new(SubmitHelperBinder {
            source: self.clone(),
            admitted: prepared.admitted.clone(),
            held,
            session_id: prepared.session_id.clone(),
            controller: prepared.controller.clone(),
            entry_fence,
        });
        let result = runtime
            .dispatch_governed_with_turn_ticket(
                &identity,
                Some(alias),
                Input::Prompt(PromptInput::new(content, None)),
                binder,
            )
            .await;
        Ok(match result {
            Ok(outcome) => PrivateOriginalSubmission::Admitted {
                session_id: outcome.admission.session_id.to_string(),
                input_id: outcome.admission.input_id.to_string(),
                deduplicated: outcome.admission.deduplicated,
                turn_ticket: match outcome.ticketed.turn {
                    TurnTracking::Tracked(ticket) => Some(ticket.to_string()),
                    TurnTracking::Unavailable(_) => None,
                },
                source_settlement: if outcome.admission.deduplicated {
                    PrivateSourceSettlement::RetryWithdrawn
                } else if outcome.settlement.is_ok() {
                    PrivateSourceSettlement::FreshAcceptancePromoted
                } else {
                    PrivateSourceSettlement::PostAdmissionPublicationFailed
                },
            },
            Err(IdentityRuntimeError::GovernedInput(GovernedInputError::AdmissionUnresolved {
                ..
            })) => PrivateOriginalSubmission::AdmissionUnresolved,
            Err(error) => {
                Self::native_submission_error_diagnostic("toolkit_helper_submission_error", &error);
                #[cfg(test)]
                aa1_helper_send_failure(&error);
                PrivateOriginalSubmission::NativeOutcomeUnavailable
            }
        })
    }
}

struct PrepareHelperBinder {
    source: Weak<PrivateOriginals>,
    admitted: Arc<AdmittedHelperWork>,
    captured: Mutex<Option<PreparedHelperController>>,
}

#[async_trait]
impl GovernedInputBinder for PrepareHelperBinder {
    async fn bind(
        &self,
        context: &GovernedBindContext,
        _input: Input,
    ) -> Result<BoundGovernedInput, String> {
        let source = self
            .source
            .upgrade()
            .ok_or("Toolkit helper source is unavailable")?;
        source
            .owner
            .check_admitted_helper(&self.admitted)
            .map_err(|_| "Toolkit helper source is unavailable")?;
        source
            .require_helper_selection(self.admitted.selection())
            .map_err(|_| "Toolkit helper selection is unavailable")?;
        let machine = source
            .machine()
            .map_err(|_| "Toolkit helper runtime is unavailable")?;
        let registration = machine
            .current_session_registration_witness(&context.session_id)
            .await
            .ok_or("Toolkit helper registration is unavailable")?;
        let member = &self.admitted.selection().member;
        let target = NativeWorkTarget {
            logical_owner: member.logical_owner.clone(),
            logical_runtime: EvidenceId::new(
                meerkat_runtime::LogicalRuntimeId::for_session(registration.session_id())
                    .to_string(),
            )
            .map_err(|_| "Toolkit helper runtime identity is unavailable")?,
            context: EvidenceId::new(registration.session_id().to_string())
                .map_err(|_| "Toolkit helper session is unavailable")?,
            context_generation: member.context_generation,
            audience: member.audience.clone(),
        };
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| "Toolkit helper preparation is unavailable")?;
        if captured.is_some() {
            return Err("Toolkit helper preparation was already captured".into());
        }
        *captured = Some(PreparedHelperController {
            source: self.source.clone(),
            admitted: self.admitted.clone(),
            session_id: context.session_id.clone(),
            target,
            controller: context.controller.clone(),
        });
        Err("Toolkit helper controller preparation precedes input submission".into())
    }

    fn retain_unresolved(&self, _settlement: Box<dyn GovernedSettlement>, _detail: &str) {
        // bind never returns input or settlement, so there is no custody here.
    }
}

struct SubmitHelperBinder {
    source: Arc<PrivateOriginals>,
    admitted: Arc<AdmittedHelperWork>,
    held: Arc<HeldSetupHelper>,
    session_id: SessionId,
    controller: ControllerModelClient,
    entry_fence: Option<Arc<dyn meerkat_mobkit::identity_first::GovernedEntryFence>>,
}

#[async_trait]
impl GovernedInputBinder for SubmitHelperBinder {
    async fn bind(
        &self,
        context: &GovernedBindContext,
        input: Input,
    ) -> Result<BoundGovernedInput, String> {
        if context.session_id != self.session_id
            || context.controller.selection() != self.controller.selection()
        {
            #[cfg(test)]
            crate::aa1_failure("helper.bind.placement", "PlacementChanged");
            return Err("Toolkit helper native placement changed".into());
        }
        self.source
            .owner
            .check_admitted_helper(&self.admitted)
            .map_err(|_| {
                #[cfg(test)]
                crate::aa1_failure("helper.bind.source", "Unavailable");
                "Toolkit helper source is unavailable"
            })?;
        self.source
            .require_helper_selection(self.admitted.selection())
            .map_err(|_| {
                #[cfg(test)]
                crate::aa1_failure("helper.bind.selection", "Unavailable");
                "Toolkit helper selection is unavailable"
            })?;
        let (input, pending) = self
            .source
            .owner
            .bind_authenticated_input(
                &self.held.source.original,
                &context.session_id,
                input,
                self.held.source.event_key.clone(),
                self.held.source.authentication.clone(),
                context.controller.clone(),
            )
            .map_err(|_error| {
                #[cfg(test)]
                crate::aa1_failure("helper.bind.input", aa1_helper_runtime_variant(&_error));
                "Toolkit helper input binding is unavailable"
            })?;
        let settlement = HelperSettlement {
            expected_session: context.session_id.clone(),
            expected_input: input.id().clone(),
            pending: Some(pending),
            held: Arc::downgrade(&self.held),
        };
        Ok(BoundGovernedInput {
            input,
            settlement: Box::new(settlement),
            entry_fence: self.entry_fence.clone(),
        })
    }

    fn retain_unresolved(&self, settlement: Box<dyn GovernedSettlement>, _detail: &str) {
        self.held
            .unresolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(settlement);
    }
}

struct HelperSettlement {
    expected_session: SessionId,
    expected_input: InputId,
    pending: Option<PendingToolkitOriginal>,
    held: Weak<HeldSetupHelper>,
}

impl GovernedSettlement for HelperSettlement {
    fn accepted(mut self: Box<Self>, admission: &GovernedAdmission) -> Result<(), String> {
        if admission.deduplicated
            || admission.session_id != self.expected_session
            || admission.input_id != self.expected_input
        {
            if let Some(held) = self.held.upgrade() {
                held.unresolved
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(self);
            }
            return Err("Toolkit helper source acknowledgement did not match".into());
        }
        self.pending
            .take()
            .ok_or_else(|| "Toolkit helper source settlement was already consumed".to_owned())?
            .admit()
            .map(|_| ())
            .map_err(|_| "Native helper was admitted but source publication failed".into())
    }
}

// Failure-only labels for the existing AA1 executor. Payloads and native
// error text stay private; the public result and settlement mapping are unchanged.
#[cfg(test)]
fn aa1_helper_send_failure(error: &IdentityRuntimeError) {
    let variant = match error {
        IdentityRuntimeError::GovernedInput(error) => match error {
            GovernedInputError::Unsupported(_) => "GovernedInputError::Unsupported",
            GovernedInputError::BindingChanged => "GovernedInputError::BindingChanged",
            GovernedInputError::Bind(_) => "GovernedInputError::Bind",
            GovernedInputError::Unbound => "GovernedInputError::Unbound",
            GovernedInputError::EntryRefused(_) => "GovernedInputError::EntryRefused",
            GovernedInputError::AdmissionUnresolved { .. } => "GovernedInputError::AdmissionUnresolved",
            GovernedInputError::Mob(error) => match error.as_ref() {
                meerkat_mob::MobError::MemberInputRefused { error, .. } => {
                    crate::aa1_failure("helper.send.member_input", aa1_helper_runtime_variant(error));
                    "MobError::MemberInputRefused"
                }
                meerkat_mob::MobError::GovernedInputUnbound { .. } => "MobError::GovernedInputUnbound",
                meerkat_mob::MobError::MemberSessionNotLive { .. } => "MobError::MemberSessionNotLive",
                meerkat_mob::MobError::MemberNotFound(_) => "MobError::MemberNotFound",
                _ => "MobError::Other",
            },
        },
        IdentityRuntimeError::UnknownIdentity(_) => "IdentityRuntimeError::UnknownIdentity",
        IdentityRuntimeError::NotAddressable(_) => "IdentityRuntimeError::NotAddressable",
        IdentityRuntimeError::CompletionUnavailable { .. } => "IdentityRuntimeError::CompletionUnavailable",
        IdentityRuntimeError::AdmissionFailed { .. } => "IdentityRuntimeError::AdmissionFailed",
        IdentityRuntimeError::ActorAdmissionTimeout { .. } => "IdentityRuntimeError::ActorAdmissionTimeout",
        IdentityRuntimeError::ActorLoopStalled { .. } => "IdentityRuntimeError::ActorLoopStalled",
        IdentityRuntimeError::ActorTerminated { .. } => "IdentityRuntimeError::ActorTerminated",
        IdentityRuntimeError::NoActiveLease(_) => "IdentityRuntimeError::NoActiveLease",
        IdentityRuntimeError::LeaseLost(_) => "IdentityRuntimeError::LeaseLost",
        IdentityRuntimeError::InvalidState { .. } => "IdentityRuntimeError::InvalidState",
        IdentityRuntimeError::StaleRuntimeAlias { .. } => "IdentityRuntimeError::StaleRuntimeAlias",
        _ => "IdentityRuntimeError::Other",
    };
    crate::aa1_failure("helper.send", variant);
}

#[cfg(test)]
fn aa1_helper_runtime_variant(error: &meerkat_runtime::RuntimeDriverError) -> &'static str {
    use meerkat_runtime::RuntimeDriverError;
    match error {
        RuntimeDriverError::InputRefused { refusal } => match refusal.kind() {
            meerkat_core::OperationRefusalKind::Denied => "RuntimeDriverError::InputRefused::Denied",
            meerkat_core::OperationRefusalKind::ReprepareRequired => "RuntimeDriverError::InputRefused::ReprepareRequired",
            meerkat_core::OperationRefusalKind::MalformedFacts => "RuntimeDriverError::InputRefused::MalformedFacts",
        },
        RuntimeDriverError::ControllerReadinessUnavailable { .. } => "RuntimeDriverError::ControllerReadinessUnavailable",
        RuntimeDriverError::ValidationFailed { .. } => "RuntimeDriverError::ValidationFailed",
        RuntimeDriverError::InputIdempotencyConflict { .. } => "RuntimeDriverError::InputIdempotencyConflict",
        RuntimeDriverError::NotReady { .. } => "RuntimeDriverError::NotReady",
        RuntimeDriverError::NotFound { .. } => "RuntimeDriverError::NotFound",
        RuntimeDriverError::Destroyed => "RuntimeDriverError::Destroyed",
        _ => "RuntimeDriverError::Other",
    }
}

fn helper_error(error: OriginalWriterError) -> PrivateOriginalError {
    match error {
        OriginalWriterError::Conflict => PrivateOriginalError::Conflict,
        OriginalWriterError::OperationDenied
        | OriginalWriterError::OperationCancelled
        | OriginalWriterError::WrongOwner => {
            PrivateOriginalError::Denied
        }
        _ => PrivateOriginalError::Unavailable,
    }
}
