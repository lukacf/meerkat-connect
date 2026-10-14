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
    pub async fn prepare(
        &self, call: ToolCallView<'_>, context: &ToolDispatchContext,
        plan: Option<&meerkat_core::ResolvedToolExecutionPlan>, agent: &str,
    ) -> Result<Option<InstalledServiceTask>, PrivateOriginalError> {
        self.prepare_selected(call, context, plan, Some(agent)).await
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
        let selected = self.selected.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        let owner = selected.lock().map_err(|_| PrivateOriginalError::Unavailable)?
            .configured().ok_or(PrivateOriginalError::Unavailable)?;
        let source = owner.host.originals.setup_result_source(context, &owner.helper).await?;
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
                contributors: &source.contributors, effect: &effect,
                input_digest: &source.operation.input_digest, context: &current,
            }, &owner.work_backend).await.map_err(|_| PrivateOriginalError::Unavailable)?;
        // This exact call owns disclosure. No historical request is a permit.
        context.check_tool_authorization(call, plan).map_err(|_| PrivateOriginalError::Denied)?;
        let agent = match proposed_agent {
            Some(agent) => agent.to_owned(),
            None => snapshot.request().host().continuation.native_original.as_ref()
                .and_then(|task| task.member.as_ref()).ok_or(PrivateOriginalError::Unavailable)?
                .member.clone(),
        };
        let task = owner.host.originals.prepare_service_task(owner.store.clone(), snapshot, call.id, &agent).await?;
        context.check_tool_authorization(call, plan).map_err(|_| PrivateOriginalError::Denied)?;
        Ok(task)
    }
}
