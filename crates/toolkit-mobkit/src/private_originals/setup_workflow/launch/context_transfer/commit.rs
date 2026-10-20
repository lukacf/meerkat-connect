//! One retained Find-fenced SQLite attempt. Recipient selection and payload
//! disclosure remain in the parent; this owner only joins the entered write.
use super::*;
use meerkat::governed_realm::helper_admission::{GovernedHelperAdmissionFence, HelperAdmissionRefusal};
use meerkat_workgraph::{WorkGraphAdmissionFence, WorkGraphError};

pub(crate) struct OwnedTransferCommit {
    admission: WorkAdmission,
    join: tokio::sync::Mutex<CommitJoin>,
}
enum CommitJoin {
    Running(tokio::task::JoinHandle<Result<WorkAdmission, PrivateOriginalError>>),
    Joined(Result<WorkAdmission, PrivateOriginalError>),
}
impl OwnedTransferCommit {
    /// The caller holds RecoveryControl::enter_transfer and its existing
    /// canonical attempt slot, then retains this owner before any await.
    pub(crate) fn start(call: ToolCallView<'_>, context: &ToolDispatchContext,
        source: Arc<ToolkitOriginalOwner>, service: WorkGraphService, key: WorkAdmissionKey,
        request: CreateWorkItemRequest, deadline_ms: u64) -> Result<Self, PrivateOriginalError>
    {
        if call.name != crate::FIND_AND_INSTALL || service.store().kind() != WorkGraphStoreKind::Sqlite {
            return Err(PrivateOriginalError::Denied);
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| PrivateOriginalError::Unavailable)?;
        let admission = service.admission_identity(key.clone(), request.clone())
            .map_err(|_| PrivateOriginalError::Conflict)?;
        let fence = GovernedHelperAdmissionFence::from_dispatch(call, context, source.clone(), Arc::from([]),
            service.default_realm_id(), service.default_namespace().clone(), admission.clone())
            .map_err(fence_refusal)?;
        let guarded = Arc::new(TransferDeadlineFence { native: fence.clone(), source, deadline_ms,
            expired: std::sync::atomic::AtomicBool::new(false) });
        let report = guarded.clone();
        let exact = admission.clone();
        let join = tokio::task::spawn_blocking(move || {
            let result = runtime.block_on(service.create_idempotent_with_fence(key, request.clone(), guarded));
            let outcome = result.map_err(|_| {
                if report.expired.load(Ordering::Acquire) { PrivateOriginalError::Denied }
                else { fence.refusal().map(fence_refusal).unwrap_or(PrivateOriginalError::Unavailable) }
            })?;
            let item = outcome.item().ok_or(PrivateOriginalError::Conflict)?;
            validate_item_identity(&service, &exact, &request, item)?;
            Ok(exact)
        });
        Ok(Self { admission, join: tokio::sync::Mutex::new(CommitJoin::Running(join)) })
    }
    pub(crate) fn admission(&self) -> &WorkAdmission { &self.admission }
    pub(crate) fn finished(&self) -> bool {
        self.join.try_lock().is_ok_and(|held| match &*held {
            CommitJoin::Running(task) => task.is_finished(), CommitJoin::Joined(_) => true,
        })
    }
    pub(crate) async fn join(&self) -> Result<WorkAdmission, PrivateOriginalError> {
        let mut held = self.join.lock().await;
        let result = match &mut *held {
            CommitJoin::Running(task) => task.await.unwrap_or(Err(PrivateOriginalError::Unavailable)),
            CommitJoin::Joined(result) => result.clone(),
        };
        *held = CommitJoin::Joined(result.clone());
        result
    }
}
struct TransferDeadlineFence {
    native: Arc<GovernedHelperAdmissionFence>,
    source: Arc<ToolkitOriginalOwner>,
    deadline_ms: u64,
    expired: std::sync::atomic::AtomicBool,
}
impl WorkGraphAdmissionFence for TransferDeadlineFence {
    fn execute_if_current(&self, realm: &str, namespace: &WorkNamespace, admission: &WorkAdmission,
        operation: Box<dyn FnOnce() -> Result<(), WorkGraphError> + '_>) -> Result<(), WorkGraphError>
    {
        self.native.execute_if_current(realm, namespace, admission, Box::new(|| {
            let now = self.source.clock().now().map_err(|_| WorkGraphError::Conflict("transfer clock unavailable".into()))?;
            if now.unix_ms >= self.deadline_ms {
                self.expired.store(true, Ordering::Release);
                return Err(WorkGraphError::Conflict("transfer request expired".into()));
            }
            operation()
        }))
    }
}
fn fence_refusal(refusal: HelperAdmissionRefusal) -> PrivateOriginalError {
    match refusal {
        HelperAdmissionRefusal::Denied => PrivateOriginalError::Denied,
        HelperAdmissionRefusal::Unavailable => PrivateOriginalError::Unavailable,
    }
}
