//! One-use native-send correlation for an exact host-owned setup peer.
//! Native MCP authority and software review still run at their ordinary doors.
//! This slot is ephemeral dispatch custody, not an approval or job registry.
use super::*;
use async_trait::async_trait;
use futures_util::FutureExt;
use meerkat_core::{
    McpServerConfig, SessionId, ToolCallView, ToolDispatchContext, ToolError, ToolMutationClass,
};
use meerkat_mcp::{
    McpCallContext, McpCallContextError, McpCallContextProvider, McpCallTarget, McpResourceTarget,
};
use std::sync::{
    Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;
use toolkit_mobkit::private_originals::InstalledSharedEntry;

const META: &str = "toolkit/shared-entry";

/// Compose after final helper projection and before native session preparation,
/// on the same factory as the normal review dispatcher. Complete configuration picks
/// this one resource-owned peer. Other destinations delegate unchanged.
/// Multiple peers compose by passing the previous provider as `delegate`.
/// An existing provider that also prepares this setup destination is refused:
/// its opaque native custody cannot be discarded or merged by this wrapper.
pub struct SharedSetupCallContext {
    pub(crate) peer: Arc<SharedSetupPeer>,
    delegate: Arc<dyn McpCallContextProvider>,
    pending: Mutex<Vec<Weak<Call>>>,
}
impl SharedSetupCallContext {
    /// Bind only after the ordinary helper projection and its optional research
    /// ceiling are final. The projection may add access, but cannot substitute
    /// this resource owner's transport, peer path or operation-name mapping.
    pub fn new(
        mut peer: SharedSetupPeer,
        helper: &crate::setup::PreparedSetupHelper,
        delegate: Arc<dyn McpCallContextProvider>,
    ) -> Result<Arc<Self>, ConnectError> {
        peer.configuration = projected_configuration(&peer.configuration, helper)?;
        Ok(Arc::new(Self {
            peer: Arc::new(peer),
            delegate,
            pending: Mutex::new(Vec::new()),
        }))
    }

    /// The retained resource, not serialized configuration, supplies this
    /// attachment projection. Native registration still owns caller lifetime.
    pub(crate) fn validates_resource(&self, helper: &crate::setup::PreparedSetupHelper) -> bool {
        helper.server() == &self.peer.configuration
            && !self.peer.entries.closing.load(Ordering::Acquire)
    }

    #[cfg(feature = "console")]
    pub(crate) fn attempt_peer(&self) -> Arc<SharedSetupPeer> {
        self.peer.clone()
    }

    #[cfg(feature = "console")]
    pub(crate) fn bind_attempt_registration(
        &self,
        member: meerkat_core::MobMemberBinding,
        session: String,
        participant: Arc<crate::application_setup::resource::SetupResourceRegistration>,
    ) -> Result<(), String> {
        self.peer.attempt.bind(member, session, participant)
    }

    pub(crate) fn selects_operation(
        &self,
        target: Option<&meerkat_core::ToolOperationTarget>,
        name: &str,
    ) -> bool {
        matches!(target, Some(meerkat_core::ToolOperationTarget::McpServerOperation {
            server, raw_operation, ..
        }) if server == &self.peer.configuration.name && raw_operation == name)
    }

    pub(crate) fn arm(
        &self,
        call: ToolCallView<'_>,
        context: &ToolDispatchContext,
        source: InstalledSharedEntry,
        preparation: Option<String>,
    ) -> Result<Dispatch, ToolError> {
        let session = match context.origin_session_id().cloned() {
            Some(session) => session,
            None => {
                let _ = source.settle();
                return Err(ToolError::access_denied(call.name));
            }
        };
        let mut pending = match self.pending.lock() {
            Ok(pending) => pending,
            Err(_) => {
                let _ = source.settle();
                return Err(ToolError::access_denied(call.name));
            }
        };
        let selected = Arc::new(Call {
            pointer: call.args.get().as_ptr() as usize,
            name: call.name.into(),
            id: call.id.into(),
            arguments: call.args.get().into(),
            session,
            source,
            preparation,
            claimed: AtomicBool::new(false),
            done: AtomicBool::new(false),
            changed: Notify::new(),
        });
        pending.retain(|value| value.strong_count() > 0);
        if pending.len() >= 128 || self.peer.entries.closing.load(Ordering::Acquire) {
            let _ = selected.source.settle();
            return Err(ToolError::access_denied(call.name));
        }
        pending.push(Arc::downgrade(&selected));
        Ok(Dispatch(selected))
    }
}

fn projected_configuration(
    raw: &McpServerConfig,
    helper: &crate::setup::PreparedSetupHelper,
) -> Result<McpServerConfig, ConnectError> {
    let selected = helper.server();
    let mut transport = selected.clone();
    transport.access = None;
    // The restricted preparer does not accept aliases. This path compares raw
    // and displayed operations only under that exact existing restriction.
    if raw.access.is_some()
        || selected.access.is_none()
        || !selected.tool_names.is_empty()
        || &transport != raw
    {
        return Err(unavailable());
    }
    Ok(selected.clone())
}

struct Call {
    // Only correlates this still-borrowed call to its nested native dispatcher.
    // The actual source capture and native final authorization supply custody.
    pointer: usize,
    name: String,
    id: String,
    arguments: String,
    session: SessionId,
    source: InstalledSharedEntry,
    preparation: Option<String>,
    claimed: AtomicBool,
    done: AtomicBool,
    changed: Notify,
}
impl Call {
    async fn done(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.done.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}
pub(crate) struct Dispatch(Arc<Call>);
impl Drop for Dispatch {
    fn drop(&mut self) {
        self.0.done.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
        // No provider/private command began, so this is definite local nonentry.
        if !self.0.claimed.load(Ordering::Acquire) {
            let _ = self.0.source.settle();
        }
    }
}

#[async_trait]
impl McpCallContextProvider for SharedSetupCallContext {
    async fn prepare(
        &self,
        target: McpCallTarget<'_>,
        call: ToolCallView<'_>,
        context: &ToolDispatchContext,
    ) -> Result<Option<McpCallContext>, McpCallContextError> {
        if target.config != &self.peer.configuration {
            return self.delegate.prepare(target, call, context).await;
        }
        let connection = target.connection_id.to_string();
        let raw_operation = target.raw_operation.to_owned();
        // Preserve the existing provider's refusal and do not throw away its
        // guard/final check on an overlapping selected destination.
        if self
            .delegate
            .prepare(target, call, context)
            .await?
            .is_some()
        {
            return Err(McpCallContextError::Denied);
        }
        let arguments =
            serde_json::from_str(call.args.get()).map_err(|_| McpCallContextError::Denied)?;
        let held = {
            let pending = self
                .pending
                .lock()
                .map_err(|_| McpCallContextError::Unavailable)?;
            let mut exact = pending.iter().filter_map(Weak::upgrade).filter(|held| {
                held.pointer == call.args.get().as_ptr() as usize
                    && held.name == call.name
                    && held.id == call.id
                    && held.arguments == call.args.get()
                    && context.origin_session_id() == Some(&held.session)
                    && !held.done.load(Ordering::Acquire)
            });
            let held = exact.next().ok_or(McpCallContextError::Denied)?;
            if exact.next().is_some()
                || raw_operation != call.name
                || held.claimed.swap(true, Ordering::AcqRel)
            {
                return Err(McpCallContextError::Denied);
            }
            held
        };
        let peer = self.peer.clone();
        let monitor = held.clone();
        let (reply, token) = tokio::sync::oneshot::channel();
        // Retain preparation and settlement before the first private await.
        // Native cancellation cannot drop a shared command or strand a token
        // between its reply and installing the settlement monitor.
        let monitoring = self.peer.entries.spawn(async move {
            if monitor.done.load(Ordering::Acquire) {
                monitor.source.settle().map_err(|_| unavailable())?;
                let _ = reply.send(Err(McpCallContextError::Denied));
                return Ok(());
            }
            let token = match peer
                .prepare_entry(
                    &connection,
                    &raw_operation,
                    &arguments,
                    monitor.preparation.as_deref(),
                )
                .await
            {
                Ok(token) => token,
                Err(
                    super::control::RequestFailure::NotSent
                    | super::control::RequestFailure::Refused,
                ) => {
                    monitor.source.settle().map_err(|_| unavailable())?;
                    let _ = reply.send(Err(McpCallContextError::Unavailable));
                    return Ok(());
                }
                Err(super::control::RequestFailure::Unknown) => {
                    // Missing transport evidence cannot release source custody.
                    let _ = reply.send(Err(McpCallContextError::Unavailable));
                    return Err(unavailable());
                }
            };
            if reply.send(Ok(token.clone())).is_ok() {
                tokio::select! {
                    _ = monitor.done() => {},
                    _ = monitor.source.closed() => {},
                    _ = peer.entries.closed() => {},
                }
            }
            // The private close is serialized with initial dispatch, not the
            // physical worker. Delayed emitted metadata cannot reenter after it.
            peer.close_entry(&token).await?;
            monitor.source.settle().map_err(|_| unavailable())?;
            peer.finish_entry(&token).await
        });
        if monitoring.is_err() {
            let _ = held.source.settle();
            return Err(McpCallContextError::Unavailable);
        }
        let token = token
            .await
            .map_err(|_| McpCallContextError::Unavailable)??;
        let source = held.source.clone();
        let metadata = [(META.to_owned(), serde_json::Value::String(token))]
            .into_iter()
            .collect();
        Ok(Some(McpCallContext::new(metadata, held).with_final_check(
            move || {
                source.enter().map_err(|_| McpCallContextError::Denied)?;
                Ok(source)
            },
        )))
    }

    async fn prepare_resource(
        &self,
        target: McpResourceTarget<'_>,
        context: &ToolDispatchContext,
    ) -> Result<Option<McpCallContext>, McpCallContextError> {
        if target.config == &self.peer.configuration {
            return Err(McpCallContextError::Denied);
        }
        self.delegate.prepare_resource(target, context).await
    }
    fn resource_authorization_target(
        &self,
        target: McpResourceTarget<'_>,
    ) -> Option<meerkat_core::authorization::OwnerQualifiedTarget> {
        if target.config == &self.peer.configuration {
            return None;
        }
        self.delegate.resource_authorization_target(target)
    }
    fn tool_mutation_class(&self, config: &McpServerConfig, operation: &str) -> ToolMutationClass {
        self.delegate.tool_mutation_class(config, operation)
    }
}

#[derive(Default)]
pub(super) struct EntryTasks {
    // Separate from commands: this one resource close task drains commands and
    // therefore must not join itself. Its handle survives close-caller loss.
    shutdown: Mutex<Option<RetainedResourceClose>>,
    closing: AtomicBool,
    changed: Notify,
    state: Mutex<EntryTaskState>,
}
#[derive(Default)]
struct EntryTaskState {
    closed: bool,
    tasks: Vec<tokio::task::JoinHandle<Result<(), ConnectError>>>,
    // A bounded owner disposition, not an ever-growing completed-task log.
    failed: bool,
}
pub(super) type RetainedResourceClose =
    Arc<tokio::sync::Mutex<tokio::task::JoinHandle<Result<(), ConnectError>>>>;
const MAX_ACTIVE_ENTRY_TASKS: usize = 2048;
impl EntryTasks {
    pub(super) fn retain_resource_close(
        &self,
        task: impl Future<Output = Result<(), ConnectError>> + Send + 'static,
    ) -> Result<RetainedResourceClose, ConnectError> {
        let mut retained = self.shutdown.lock().map_err(|_| unavailable())?;
        if retained.is_some() {
            return Err(unavailable());
        }
        self.closing.store(true, Ordering::Release);
        self.changed.notify_waiters();
        let handle = Arc::new(tokio::sync::Mutex::new(tokio::spawn(task)));
        *retained = Some(handle.clone());
        Ok(handle)
    }
    #[cfg(test)]
    pub(super) fn retained_resource_close(&self) -> Option<RetainedResourceClose> {
        self.shutdown.lock().unwrap().clone()
    }
    pub(super) fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }
    fn spawn(
        &self,
        task: impl Future<Output = Result<(), ConnectError>> + Send + 'static,
    ) -> Result<(), ConnectError> {
        self.spawn_command(task, false)
    }

    pub(super) fn spawn_command(
        &self,
        task: impl Future<Output = Result<(), ConnectError>> + Send + 'static,
        cleanup: bool,
    ) -> Result<(), ConnectError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        let mut failed = state.failed;
        state.tasks.retain_mut(|task| {
            if !task.is_finished() {
                return true;
            }
            // Poll the borrowed handle: even an unexpectedly pending result
            // remains owned. Completed failures survive handle reclamation.
            match (&mut *task).now_or_never() {
                Some(Ok(Ok(()))) => false,
                Some(_) => {
                    failed = true;
                    false
                }
                None => true,
            }
        });
        state.failed = failed;
        if state.closed
            || (self.closing.load(Ordering::Acquire) && !cleanup)
            || state.tasks.len() >= MAX_ACTIVE_ENTRY_TASKS
        {
            return Err(unavailable());
        }
        state.tasks.push(tokio::spawn(task));
        Ok(())
    }
    async fn closed(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.closing.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
    pub(super) async fn close(&self) -> Result<(), ConnectError> {
        self.closing.store(true, Ordering::Release);
        self.changed.notify_waiters();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(75);
        let mut failed = false;
        loop {
            let tasks = {
                let mut state = self.state.lock().map_err(|_| unavailable())?;
                failed |= state.failed;
                if state.tasks.is_empty() {
                    state.closed = true;
                    state.failed = failed;
                    break;
                }
                std::mem::take(&mut state.tasks)
            };
            for mut task in tasks {
                match tokio::time::timeout_at(deadline, &mut task).await {
                    Ok(Ok(Ok(()))) => {}
                    Ok(_) => failed = true,
                    Err(_) => {
                        // Forced resource-owner cancellation preserves unknown
                        // source outcomes and remains an unsuccessful close.
                        task.abort();
                        let _ = task.await;
                        failed = true;
                    }
                }
            }
            // A settling monitor may enqueue its exact close/finish command.
            // Drain those owned commands before publishing terminal closure.
        }
        if failed { Err(unavailable()) } else { Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared() -> (McpServerConfig, crate::setup::PreparedSetupHelper) {
        let bytes = br#"{"mcpServers":{"toolkit-setup":{"command":"/usr/bin/env","args":["-i","/product/python","-I","/product/local_session.py","--shared-peer","/private/peer-a"]}}}"#;
        let connection =
            || crate::setup::PreparedSetupConnection::from_preparer_output(bytes).unwrap();
        let raw = connection().into_server();
        let helper = connection()
            .for_mobkit_helper(
                meerkat_core::MobMemberBinding {
                    mob_id: "host".into(),
                    role: "research".into(),
                    member: "helper-a".into(),
                },
                crate::setup::SetupHelperTools::CheckedInstallation,
            )
            .unwrap();
        (raw, helper)
    }

    #[test]
    fn shared_provider_binds_the_actual_projected_helper_configuration() {
        let (raw, helper) = prepared();
        assert!(raw.access.is_none());
        let selected = projected_configuration(&raw, &helper).unwrap();
        assert_eq!(&selected, helper.server());
        assert_ne!(selected, raw);
        assert!(
            selected
                .access
                .as_ref()
                .unwrap()
                .allowed_operations
                .contains("setup_selected_install")
        );
        let mut without_access = selected;
        without_access.access = None;
        assert_eq!(without_access, raw);
    }

    #[test]
    fn shared_provider_refuses_a_foreign_peer_or_unprojected_access() {
        let (raw, helper) = prepared();
        let mut foreign = raw.clone();
        let meerkat_core::mcp_config::McpTransportConfig::Stdio(ref mut launch) = foreign.transport
        else {
            panic!("prepared stdio")
        };
        launch.args.last_mut().unwrap().push_str("-foreign");
        assert!(projected_configuration(&foreign, &helper).is_err());
        let mut already_projected = raw.clone();
        already_projected.access = helper.server().access.clone();
        assert!(projected_configuration(&already_projected, &helper).is_err());
        let mut aliased = raw;
        aliased
            .tool_names
            .insert("setup_selected_install".into(), "other".into());
        assert!(projected_configuration(&aliased, &helper).is_err());
    }

    async fn completed(tasks: &EntryTasks) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if tasks
                    .state
                    .lock()
                    .unwrap()
                    .tasks
                    .iter()
                    .all(|task| task.is_finished())
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned entry tasks settle");
    }

    #[tokio::test]
    async fn completed_entry_tasks_do_not_exhaust_host_and_close_joins_active() {
        let tasks = EntryTasks::default();
        for _ in 0..=MAX_ACTIVE_ENTRY_TASKS {
            tasks.spawn(async { Ok(()) }).unwrap();
            assert_eq!(tasks.state.lock().unwrap().tasks.len(), 1);
            completed(&tasks).await;
        }
        let (release, held) = tokio::sync::oneshot::channel();
        tasks
            .spawn(async move { held.await.map_err(|_| unavailable()) })
            .unwrap();
        assert_eq!(tasks.state.lock().unwrap().tasks.len(), 1);
        let close = tasks.close();
        tokio::pin!(close);
        assert!(close.as_mut().now_or_never().is_none());
        assert!(tasks.spawn(async { Ok(()) }).is_err());
        release.send(()).unwrap();
        close.await.unwrap();
        assert!(tasks.state.lock().unwrap().tasks.is_empty());
        assert!(!tasks.state.lock().unwrap().failed);
    }

    #[tokio::test]
    async fn closing_owner_joins_commands_enqueued_by_its_settlement_task() {
        let tasks = Arc::new(EntryTasks::default());
        let settling = tasks.clone();
        let (arrived, reached) = tokio::sync::oneshot::channel();
        let (release, held) = tokio::sync::oneshot::channel();
        tasks
            .spawn(async move {
                settling.closed().await;
                settling.spawn_command(
                    async move {
                        let _ = arrived.send(());
                        held.await.map_err(|_| unavailable())
                    },
                    true,
                )
            })
            .unwrap();
        let close = tasks.close();
        tokio::pin!(close);
        assert!(close.as_mut().now_or_never().is_none());
        reached.await.unwrap();
        assert!(close.as_mut().now_or_never().is_none());
        release.send(()).unwrap();
        close.await.unwrap();
        assert!(tasks.state.lock().unwrap().closed);
        assert!(tasks.spawn_command(async { Ok(()) }, true).is_err());
    }

    #[tokio::test]
    async fn reaped_entry_failure_remains_an_owner_close_failure() {
        let tasks = EntryTasks::default();
        tasks.spawn(async { Err(unavailable()) }).unwrap();
        completed(&tasks).await;
        tasks.spawn(async { Ok(()) }).unwrap();
        assert_eq!(tasks.state.lock().unwrap().tasks.len(), 1);
        assert!(tasks.state.lock().unwrap().failed);
        completed(&tasks).await;
        assert!(tasks.close().await.is_err());
        assert!(tasks.state.lock().unwrap().tasks.is_empty());
        assert!(tasks.state.lock().unwrap().failed);
    }
}
