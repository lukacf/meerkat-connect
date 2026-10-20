//! Fresh local service instructions selected through the real helper task.
//! The source and acquisition owners remain the existing installed instances.
use super::*;
use crate::private_originals::InstalledServiceTask;
use meerkat_core::ToolCallView;
use std::sync::{Mutex, Weak};
use toolkit_store::EffectKey;

/// A weak view of this host's existing optional acquisition selection. Factory
/// construction precedes bootstrap, so resolve that same selection at dispatch.
#[derive(Clone)]
pub struct InstalledServiceTaskSource {
    selected: Weak<Mutex<AcquisitionBootstrap>>,
}
impl InstalledServiceTaskSource {
    pub(crate) fn new(selected: &Arc<Mutex<AcquisitionBootstrap>>) -> Self {
        Self { selected: Arc::downgrade(selected) }
    }
    /// Join only the physical selection returned on this helper's private
    /// Controller channel. Ordinary helper/source capture supplies acquisition
    /// and WorkGraph identities; none are accepted from tool arguments.
    pub async fn join_shared_preparation(
        &self, call: ToolCallView<'_>, context: &ToolDispatchContext,
        plan: Option<&meerkat_core::ResolvedToolExecutionPlan>,
        selection: &meerkat_toolkit::setup::SharedPreparationSelection,
        resource: Arc<dyn crate::private_originals::SharedPreparationResource>,
    ) -> Result<crate::private_originals::InstalledSharedPreparation, PrivateOriginalError> {
        let task = self.prepare_selected(call, context, plan, None).await?
            .ok_or(PrivateOriginalError::Unavailable)?;
        let selected = self.selected.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let owner = selected.lock().map_err(|_| PrivateOriginalError::Unavailable)?
            .configured().ok_or(PrivateOriginalError::Unavailable)?;
        context.check_tool_authorization(call, plan).map_err(|_| PrivateOriginalError::Denied)?;
        let member = task.join_shared_preparation(selection, owner.work_backend.clone(), resource).await?;
        context.check_tool_authorization(call, plan).map_err(|_| PrivateOriginalError::Denied)?;
        member.check_current().await?;
        Ok(member)
    }
    /// Reserve the captured source for this exact native dispatch. A joined
    /// member is required for selected-install effects; initial observations
    /// and selected-check use the same source fence before P exists.
    pub async fn reserve_shared_entry(
        &self, call: ToolCallView<'_>, context: &ToolDispatchContext,
        plan: Option<&meerkat_core::ResolvedToolExecutionPlan>,
        member: Option<&crate::private_originals::InstalledSharedPreparation>,
    ) -> Result<crate::private_originals::InstalledSharedEntry, PrivateOriginalError> {
        let task = self.prepare_selected(call, context, plan, None).await?
            .ok_or(PrivateOriginalError::Unavailable)?;
        let entry = task.reserve_shared_entry(member).await?;
        if context.check_tool_authorization(call, plan).is_err() {
            // No private transport command has been prepared on this path.
            entry.settle()?;
            return Err(PrivateOriginalError::Denied);
        }
        Ok(entry)
    }
    /// Consume a shared-stop handoff only for this actual native helper's
    /// current captured acquisition. Historical job visibility is insufficient.
    pub async fn leave_shared_preparation(
        &self, call: ToolCallView<'_>, context: &ToolDispatchContext,
        plan: Option<&meerkat_core::ResolvedToolExecutionPlan>,
        member: &crate::private_originals::InstalledSharedPreparation,
    ) -> Result<serde_json::Value, PrivateOriginalError> {
        if call.name != "setup_stop" { return Err(PrivateOriginalError::Denied); }
        let task = self.prepare_selected(call, context, plan, None).await?
            .ok_or(PrivateOriginalError::Unavailable)?;
        context.check_tool_authorization(call, plan).map_err(|_| PrivateOriginalError::Denied)?;
        task.leave_shared_preparation(member).await
    }
    pub async fn complete_shared_preparation(
        &self, call: ToolCallView<'_>, context: &ToolDispatchContext,
        plan: Option<&meerkat_core::ResolvedToolExecutionPlan>,
        member: &crate::private_originals::InstalledSharedPreparation,
    ) -> Result<(), PrivateOriginalError> {
        if call.name != "setup_selected_install" { return Err(PrivateOriginalError::Denied); }
        let task = self.prepare_selected(call, context, plan, None).await?
            .ok_or(PrivateOriginalError::Unavailable)?;
        context.check_tool_authorization(call, plan).map_err(|_| PrivateOriginalError::Denied)?;
        task.complete_shared_preparation(member).await
    }
    pub async fn prepare(
        &self, call: ToolCallView<'_>, context: &ToolDispatchContext,
        plan: Option<&meerkat_core::ResolvedToolExecutionPlan>, agent: &str,
    ) -> Result<Option<InstalledServiceTask>, PrivateOriginalError> {
        self.prepare_selected(call, context, plan, Some(agent)).await
    }
    /// Prepare only this helper's captured waiting consumer through the same
    /// source, audience and currentness checks. This performs no review or
    /// effect and does not accept or resolve a proposed member name.
    pub async fn prepare_captured_consumer(
        &self, call: ToolCallView<'_>, context: &ToolDispatchContext,
        plan: Option<&meerkat_core::ResolvedToolExecutionPlan>,
    ) -> Result<Option<InstalledServiceTask>, PrivateOriginalError> {
        self.prepare_selected(call, context, plan, None).await
    }
    /// Public service review may select this member's already configured setup
    /// capability for the fresh task. Other preparation surfaces keep their
    /// existing capture contract and do not validate this optional selection.
    pub async fn prepare_public_service(
        &self, call: ToolCallView<'_>, context: &ToolDispatchContext,
        plan: Option<&meerkat_core::ResolvedToolExecutionPlan>,
    ) -> Result<Option<InstalledServiceTask>, PrivateOriginalError> {
        self.prepare_selected_with_setup(call, context, plan, None, true).await
    }
    /// Software review has no proposed target principal. Select the waiting
    /// member from this exact helper's existing canonical acquisition custody.
    pub async fn prepare_software(
        &self, call: ToolCallView<'_>, context: &ToolDispatchContext,
        plan: Option<&meerkat_core::ResolvedToolExecutionPlan>,
    ) -> Result<Option<InstalledServiceTask>, PrivateOriginalError> {
        self.prepare_selected(call, context, plan, None).await
    }
    async fn prepare_selected(
        &self, call: ToolCallView<'_>, context: &ToolDispatchContext,
        plan: Option<&meerkat_core::ResolvedToolExecutionPlan>, proposed_agent: Option<&str>,
    ) -> Result<Option<InstalledServiceTask>, PrivateOriginalError> {
        self.prepare_selected_with_setup(call, context, plan, proposed_agent, false).await
    }
    async fn prepare_selected_with_setup(
        &self, call: ToolCallView<'_>, context: &ToolDispatchContext,
        plan: Option<&meerkat_core::ResolvedToolExecutionPlan>, proposed_agent: Option<&str>,
        select_setup: bool,
    ) -> Result<Option<InstalledServiceTask>, PrivateOriginalError> {
        let selected = self.selected.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let owner = selected.lock().map_err(|_| PrivateOriginalError::Unavailable)?
            .configured().ok_or(PrivateOriginalError::Unavailable)?;
        let source = owner.host.originals.setup_result_source_from(context, &owner.helper_selections()).await?;
        let operation = Id::new(source.operation.acquisition.id.clone())
            .map_err(|_| PrivateOriginalError::Conflict)?;
        let effect = EffectKey { record: source.operation.acquisition.clone(), id: source.operation.effect.clone() };
        let authorization = context.work_authorization().ok_or(PrivateOriginalError::Denied)?;
        let current = source.context.borrowed(authorization);
        let store = SetupStore::new_conditional(owner.store.as_ref(), owner.scope.clone())
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let (snapshot, _) = store.helper_result_snapshot(&operation,
            &meerkat_toolkit::setup::SetupHelperResultAccess {
                helper: &source.helper, source: &source.source,
                contributors: &source.contributors,
                contributor_sources: &source.contributor_sources,
                ancestor_sources: &source.ancestor_sources, effect: &effect,
                input_digest: &source.operation.input_digest, context: &current,
            }, &owner.work_backend).await.map_err(|_| PrivateOriginalError::Unavailable)?;
        let selected = owner.selected_helper(snapshot.request()).map_err(|_| PrivateOriginalError::Denied)?;
        if selected.helper.member != source.selected_helper {
            return Err(PrivateOriginalError::Denied);
        }
        // This exact call owns disclosure. No historical request is a permit.
        context.check_tool_authorization(call, plan).map_err(|_| PrivateOriginalError::Denied)?;
        let agent = match proposed_agent {
            Some(agent) => agent.to_owned(),
            None => snapshot.request().host().continuation.native_original.as_ref()
                .and_then(|task| task.member.as_ref()).ok_or(PrivateOriginalError::Unavailable)?
                .member.clone(),
        };
        let task = owner.host.originals.prepare_service_task(owner.store.clone(), snapshot, call.id, &agent).await?;
        let task = if select_setup {
            task.map(|task| task.select_configured_setup(&selected.helper, &selected.member,
                context.origin_session_id().ok_or(PrivateOriginalError::Denied)?)).transpose()?
        } else { task };
        context.check_tool_authorization(call, plan).map_err(|_| PrivateOriginalError::Denied)?;
        Ok(task)
    }
}
