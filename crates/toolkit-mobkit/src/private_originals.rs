//! Application-authenticated source facts received on the inherited host pipe.
//!
//! The parent authenticates provider events before calling this private API.
//! Toolkit retains their exact binding evidence in the existing ToolkitStore;
//! native grants and runtime admission remain separate owners. Public RPC never
//! dispatches these methods, and no wire field can supply grants or principals.

use crate::original_ingress::{OriginalWriterError, RetainedToolkitOriginal, ToolkitOriginalOwner};
use meerkat_authorization_contracts::{constraints::ResourceDomain, evidence::EvidenceId};
use meerkat_core::{PrincipalRef, RealmId};
use meerkat_runtime::MeerkatMachine;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use toolkit_package::{Id, canonical_json};
use toolkit_store::{
    AdmissionRequest, RecordData, StoreKey, StoreScope, StoredRecord, ToolkitStore, Transition,
};

pub(crate) mod acquisition;
pub(crate) mod setup_results;
mod setup_admission;
pub(crate) mod setup_helpers;
pub(crate) mod setup_workflow;
#[cfg(test)]
pub(crate) use setup_workflow::OwnedTransferCommit;
pub use setup_workflow::{InstalledWorkflowPlanning, InstalledWorkflowMember, InstalledWorkflowContextTransfer, InstalledWorkflowContext, WorkflowContextObservation, WorkflowDeliveryObservation};
pub(crate) use setup_workflow::WorkflowLaunchObservation;
pub(crate) mod service_grants;
mod governed_submit;
mod cold_service_admission;
mod cold_setup_admission;
mod planning_source_evidence;
mod console_ingress;
mod controller_setup;
mod setup_request;
mod configured_setup;
pub(crate) use configured_setup::service::ServiceSetupSelection;
mod setup_targets;
pub use setup_request::PrivateSetupRequestSelection;
mod first_input;
#[cfg(test)]
mod source_locator_tests;
mod service_approved_input;
mod service_input_receipt;
pub use service_input_receipt::{PrivateServiceInputObservation, PrivateServiceInputReceipt,
    PrivateServiceInputReport, PrivateReceiptWitness, PrivateReceiptScope};
pub(crate) mod source_status;
pub(crate) mod service_recovery;
pub use service_approved_input::{
    InstalledServiceTask, InstalledSharedEntry, InstalledSharedPreparation, SharedPreparationLeave, SharedPreparationResource, PreparedServiceInstruction, ServiceMcpPersistenceProposal,
    PublicServiceBatchEntry, PreparedPublicServiceBatch, PreparedPublicInstruction,
};
pub use crate::installed_host::tool_policy::{ServiceToolPolicySelection, ServiceToolInvocation,
    MemberPolicyLifetime, ServiceToolPolicyVersion, ServiceToolPolicyProposal, ServiceToolPolicyApproval,
    ActiveMemberToolPolicyDecision, ApplicationToolPolicyRecoveryRequest, ApplicationToolPolicyRecoveryDecision,
    ServiceToolPolicyNativeOutcome, ServiceToolPolicyObservation};
pub use service_approved_input::application::{ApplicationServicePolicy, ApplicationServicePolicyRequest,
    ApplicationServicePolicyDecision, ApplicationServicePolicyReservation, InstalledApplicationServicePolicy,
    ApplicationServicePreparation, PreparedApplicationServiceInstruction};
pub use service_approved_input::application::{ApplicationServiceParentAuthorizer,
    ServiceParentAdministrationReservation, ServiceParentAuthorization,
    ServiceParentAuthorizationProposal, ServiceParentAuthorizationRequest,
    ApplicationServiceOperation, ApplicationServiceOperationControl, ApplicationServicePreparedStatus,
    ServiceParentOperationObserver, ServiceParentOperationObservation, ServiceParentOperationOutcome,
    ServiceParentCustody, ServiceParentOperationReason};
pub(crate) use service_approved_input::application::{ServiceParentAuthorizationEvidence,
    ServiceOperationCurrent, ServiceOperationError, ServiceOperationProgress};
#[cfg(test)]
pub(crate) use governed_submit::tests::first_input_tests::FirstFixture as ContinuationFixture;
pub use controller_setup::LocalControllerSetup;
pub use governed_submit::{PrivateOriginalSubmission, PrivateOriginalSubmit, PrivateSourceSettlement};
pub use service_grants::{
    PrivateAccessChoice, PrivateServiceAccessDecision, PrivateServiceGrantObservation,
    PrivateServiceGrantRef, PrivateServiceGrantState, PrivateServiceMcpAccessDecision,
    PrivateServiceMcpPermission, PrivateServiceMcpLiveAttachment, PrivateServiceMcpCatalog, ServiceMcpSelection,
};

const SOURCE_SCHEMA: &str = "toolkit.authenticated-source-event";
const SOURCE_VERSION: u32 = 3;

pub(crate) fn same_source_origin(left: &StoredRecord, right: &StoredRecord) -> bool {
    let decode = |record: &StoredRecord| -> Option<SourceRecord> {
        if record.data.schema != SOURCE_SCHEMA || record.data.version != SOURCE_VERSION { return None; }
        serde_json::from_value(record.data.body.clone()).ok()
    };
    match (decode(left), decode(right)) {
        (Some(left), Some(right)) => left.source == right.source && left.event == right.event
            && left.approved_task == right.approved_task
            && left.setup_request == right.setup_request
            && left.configured_setup == right.configured_setup
            && left.planning_source_evidence == right.planning_source_evidence,
        _ => false,
    }
}

/// An observation in the application's selected source domain. The domain and
/// qualified authority come from the installed route, never this wire value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateSourceEvidence {
    pub resource_id: EvidenceId,
    pub revision: EvidenceId,
    pub sha256: String,
}

/// Immutable event facts asserted by the actual trusted application process.
/// `route` selects its installed exact route; it cannot create a route or widen
/// its requester, executor, audience, controller or operation policy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateAuthenticatedEvent {
    pub route: Id,
    pub original: EvidenceId,
    pub occurrence: EvidenceId,
    pub original_authentication: PrivateSourceEvidence,
    pub root_event: PrivateSourceEvidence,
    /// Previously admitted native originals, not provider rows coalesced into
    /// this first original. The application's root-event digest commits its
    /// exact ordered raw source membership separately.
    pub contributors: Vec<EvidenceId>,
    /// Digest of the exact content subsequently handed to native input binding.
    /// The original message stays with its application; this record has no body.
    pub content_sha256: String,
}

/// Historical source correlation, not a permission or native input receipt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOriginalRef {
    pub route: Id,
    pub original: EvidenceId,
    pub event_sha256: String,
}

/// Durable original cancellation and explicit task-child revocation are
/// distinct observations. Neither reports run/descendant/controller settlement.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOriginalCancellation {
    OperationsCancelled,
    /// Source cancellation and workflow departure succeeded. An unresolved
    /// workflow close obligation remains for host-owned recovery. This is not
    /// a runtime, process, controller or descendant settlement observation.
    OperationsCancelledCleanupPending,
    OperationGrantRevoked,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOriginalRetention {
    RetainedPendingNativeAdmission,
}

#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error, Debug)]
pub enum PrivateOriginalError {
    #[error("authenticated original source is unavailable")]
    Unavailable,
    #[error("authenticated original source conflicts with retained evidence")]
    Conflict,
    #[error("authenticated original route was refused")]
    Denied,
}

/// Constructed by the installed Rust policy adapter from the selected host
/// policy. No deserializer or public setter accepts these current owner facts.
#[derive(Clone)]
pub struct PrivateOriginalRoute {
    pub id: Id,
    pub grant_caller: PrincipalRef,
    pub application_parent: Option<Vec<meerkat_authorization_contracts::grant::GrantLineageRef>>,
    /// Separately selected operator-to-application controller parent. Absence
    /// cannot inherit the operation parent or another route's controller grant.
    pub controller_parent: Option<Vec<meerkat_authorization_contracts::grant::GrantLineageRef>>,
    pub grant_target: Id,
    pub grant_audience: meerkat_authorization_contracts::constraints::AudienceRef,
    pub realm: RealmId,
    pub requester: PrincipalRef,
    pub ingress_actor: PrincipalRef,
    pub logical_executor: PrincipalRef,
    pub represented_subject: Option<PrincipalRef>,
    pub source_authority: PrincipalRef,
    pub authentication_domain: ResourceDomain,
    pub event_domain: ResourceDomain,
}

/// Immutable facts from the selected source owner at initial retention. These
/// are historical source identity, not retained permission or route policy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceFacts {
    realm: RealmId,
    ingress: ResourceDomain,
    requester: PrincipalRef,
    ingress_actor: PrincipalRef,
    logical_executor: PrincipalRef,
    represented_subject: Option<PrincipalRef>,
    source_authority: PrincipalRef,
    authentication_domain: ResourceDomain,
    event_domain: ResourceDomain,
}

impl SourceFacts {
    fn from_route(route: &PrivateOriginalRoute, ingress: &ResourceDomain) -> Self {
        Self {
            realm: route.realm.clone(),
            ingress: ingress.clone(),
            requester: route.requester.clone(),
            ingress_actor: route.ingress_actor.clone(),
            logical_executor: route.logical_executor.clone(),
            represented_subject: route.represented_subject.clone(),
            source_authority: route.source_authority.clone(),
            authentication_domain: route.authentication_domain.clone(),
            event_domain: route.event_domain.clone(),
        }
    }

    fn validate(&self) -> Result<(), PrivateOriginalError> {
        if [
            &self.requester,
            &self.ingress_actor,
            &self.logical_executor,
            &self.source_authority,
            &self.ingress.authority,
            &self.authentication_domain.authority,
            &self.event_domain.authority,
        ]
        .iter()
        .any(|principal| principal.validate_qualified().is_err())
            || self
                .represented_subject
                .as_ref()
                .is_some_and(|principal| principal.validate_qualified().is_err())
        {
            return Err(PrivateOriginalError::Conflict);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRecord {
    /// Cleanup custody for exact shared preparations admitted by this source.
    /// The SetupStore P record owns membership and delivery. These locators
    /// are retained before join and never authorize an effect or disclosure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    shared_preparations: Vec<meerkat_toolkit::setup::SharedPreparationMember>,
    /// Explicit reviewed setup-only choice for this still-unbound original.
    /// Native resolution and the retained operator decision remain authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    setup_request: Option<PrivateSetupRequestSelection>,
    /// Exact configured first-bind choice, retained before any child issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    configured_setup: Option<configured_setup::ConfiguredSetupSelection>,
    /// Verified native setup-child facts for exact pre-bind compensation only.
    /// This is never an admission or liveness observation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    service_setup_children: Vec<configured_setup::service::ServiceSetupChildObservation>,
    source: SourceFacts,
    event: PrivateAuthenticatedEvent,
    operation_cancelled: bool,
    /// Exact terminal attachment cause committed atomically with B cancellation.
    /// It proves neither native non-entry nor eligibility to resume the parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service_attachment_failure: Option<meerkat_toolkit::setup::ApprovedServiceAttachmentFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service_attachment_observation:
        Option<meerkat_toolkit::setup::ApprovedServiceAttachmentObservation>,
    /// Exact batch member that supplied the terminal observation. This is
    /// evidence only, committed with the same cancellation as the failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service_attachment_member: Option<PrivateServiceGrantRef>,
    /// An exact business-task link, never an authority contributor. Created only
    /// by an authenticated reviewed or application-policy access path after
    /// native task child issuance. It never replays the prior original.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approved_task: Option<service_approved_input::ApprovedTaskLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service_admission: Option<service_approved_input::ServiceInputAdmission>,
    /// Explicit host selection to retain planning-source input evidence.
    /// It grants neither source custody nor permission to deliver context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    planning_source_evidence: Option<planning_source_evidence::PlanningSourceEvidence>,
    /// Exact bound B, selected stock-operator setup A or selected planning input retained before
    /// native submission. The legacy field name remains stable on disk. This
    /// is historical evidence, with no process ingress or resume capability.
    /// Older rows without it cannot be used for cold admission recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bound_service_input: Option<cold_service_admission::RetainedBoundInput>,
    final_association:
        Option<meerkat_authorization_contracts::work_association::InputAuthorityAssociation>,
}

/// Process-local custody alongside the existing canonical original. Native
/// unresolved submissions remain here until their native owner can settle them.
/// This is neither another input ledger nor a permission or completion record.
struct HeldPrivateOriginal {
    reference: PrivateOriginalRef,
    original: Arc<RetainedToolkitOriginal>,
    service_mcp: Vec<service_grants::RetainedServiceMcpAccess>,
    // Selected during the existing exact canonical binding read. This only
    // requests historical Input persistence, never native admission/custody.
    retain_bound_input: bool,
    // The actual Console binder installs this process owner once. A later
    // setup request inherits custody by its exact original association.
    console_login: OnceLock<crate::private_host::ConsoleLoginHandle>,
    unresolved: Mutex<Vec<Arc<governed_submit::PendingOriginalAdmission>>>,
    service_attachments: Mutex<Vec<Arc<service_approved_input::attachment::HeldServiceAttachment>>>,
    shared_preparations: Mutex<Vec<service_approved_input::shared_preparation::HeldSharedPreparation>>,
    setup_workflow: OnceLock<Arc<setup_workflow::HeldSetupWorkflow>>,
    workflow_selections: Mutex<Vec<setup_workflow::InvocationPlanning>>,
    workflow_plans: Mutex<Vec<Arc<setup_workflow::InstalledWorkflowPlanning>>>,
}

/// Exact software selection retained with an application access decision.
/// This is product-owned data, not a grant, approval or executable capability.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedApplicationInstallation {
    configuration: serde_json::Value,
    document: serde_json::Value,
}
impl RetainedApplicationInstallation {
    fn configuration(&self) -> Result<meerkat_core::McpServerConfig, PrivateOriginalError> {
        let config: meerkat_core::McpServerConfig = serde_json::from_value(self.configuration.clone())
            .map_err(|_| PrivateOriginalError::Denied)?;
        if serde_json::to_value(&config).map_err(|_| PrivateOriginalError::Conflict)? != self.configuration
            || !self.document.is_object()
            || canonical_json(self).map_err(|_| PrivateOriginalError::Conflict)?.len() > 1024 * 1024
        { return Err(PrivateOriginalError::Denied); }
        Ok(config)
    }
    fn validate(&self, decision: &PrivateServiceMcpAccessDecision) -> Result<(), PrivateOriginalError> {
        let config = self.configuration()?;
        if config.name != decision.permission.connection.as_str()
            || digest(&canonical_json(&config).map_err(|_| PrivateOriginalError::Conflict)?) != decision.connection_revision.as_str()
        { return Err(PrivateOriginalError::Denied); }
        Ok(())
    }
}

/// Constructed only after the installed owner has reopened the exact current
/// source, access decision and native parent. There is no wire constructor.
pub struct ApplicationInstallationReadback {
    selected: RetainedApplicationInstallation,
}
impl ApplicationInstallationReadback {
    pub fn document(&self) -> &serde_json::Value { &self.selected.document }
    pub fn configuration(&self) -> Result<meerkat_core::McpServerConfig, PrivateOriginalError> {
        self.selected.configuration()
    }
}

/// One exact product document selected from the actual retained batch review.
/// Only the operator parent owner can construct this evidence projection.
pub struct ReviewedBatchInstallation { document: serde_json::Value }
impl ReviewedBatchInstallation {
    pub(crate) fn new(document: serde_json::Value) -> Self { Self { document } }
    pub fn document(&self) -> &serde_json::Value { &self.document }
}

/// Distinct retained authorization paths for the same package verifier.
pub enum ServiceInstallationReadbackSource {
    SettledReview(meerkat_core::approval::ApprovalRecord),
    ReviewedBatchMember(ReviewedBatchInstallation),
    ApplicationPolicy(ApplicationInstallationReadback),
}

/// One shared Rust adapter for Python/TypeScript parent processes. The actual
/// selected native owner supplies routes and cancellation authority at native
/// composition, while the parent's private command supplies source facts only.
/// The installed package owner rechecks the exact retained human review.
/// This is a read-only software observation, never native attachment authority.
#[async_trait::async_trait]
pub trait ServiceInstallationReadback: Send + Sync {
    /// Called only by the installed host's joined recovery work. Implementations
    /// must settle any entered verifier before returning or host shutdown.
    async fn readback(
        &self,
        review: &meerkat_core::approval::ApprovalRecord,
    ) -> Result<meerkat_core::McpServerConfig, PrivateOriginalError>;
    /// Existing human-review adapters stay unchanged. Application support must
    /// explicitly verify the retained product document and exact configuration.
    async fn readback_source(&self, source: &ServiceInstallationReadbackSource)
        -> Result<meerkat_core::McpServerConfig, PrivateOriginalError> {
        match source {
            ServiceInstallationReadbackSource::SettledReview(review) => self.readback(review).await,
            ServiceInstallationReadbackSource::ApplicationPolicy(_) | ServiceInstallationReadbackSource::ReviewedBatchMember(_) => Err(PrivateOriginalError::Denied),
        }
    }
}

pub struct PrivateOriginals {
    scope: StoreScope,
    store: Arc<dyn ToolkitStore>,
    owner: Arc<ToolkitOriginalOwner>,
    routes: OnceLock<Vec<PrivateOriginalRoute>>,
    retained: Mutex<Vec<Arc<HeldPrivateOriginal>>>,
    // Internal helper custody stays in this same source adapter. These are
    // keepers for native settlement, not a second source or input ledger.
    helper_sources: Mutex<Vec<Arc<setup_helpers::HeldSetupHelper>>>,
    machine: OnceLock<Weak<MeerkatMachine>>,
    identity_runtime: OnceLock<meerkat_mobkit::identity_first::WeakPublicIdentityRuntime>,
    controller_pin_source: OnceLock<Weak<dyn meerkat_mobkit::identity_first::ControllerPinSource>>,
    host_lifetime: OnceLock<Weak<meerkat_toolkit::host_lifetime::NativeHostLifetime>>,
    installation_readback: OnceLock<Arc<dyn ServiceInstallationReadback>>,
    pub(crate) service_tool_policy: OnceLock<Arc<crate::installed_host::tool_policy::service_policy::ServicePolicyOwner>>,
}

impl PrivateOriginals {
    pub(crate) fn bind_service_tool_policy(&self,
        owner: Arc<crate::installed_host::tool_policy::service_policy::ServicePolicyOwner>,
    ) -> Result<(), meerkat_toolkit::host_lifetime::control::HostLifetimeError> {
        if let Some(existing) = self.service_tool_policy.get() {
            return if Arc::ptr_eq(existing, &owner) { Ok(()) } else { Err(meerkat_toolkit::host_lifetime::control::HostLifetimeError::InvalidSelection) };
        }
        self.service_tool_policy.set(owner).map_err(|_| meerkat_toolkit::host_lifetime::control::HostLifetimeError::InvalidSelection)
    }
    /// The existing native owner publication, shared with this host lifetime.
    /// Forwarding it creates neither an issuer nor an independent login epoch.
    pub(crate) fn authorization_publication(
        &self,
    ) -> meerkat_authorization::publication::LocalAuthorizationPublication {
        self.owner.publication()
    }

    /// Reach the operator presenter only through the actual local gateway.
    /// These are its already-open source/store owners, never caller-supplied
    /// handles or decoded authority. Selected policy is rechecked by setup.
    pub(crate) fn local_operator_setup(
        &self,
        lifetime: Arc<meerkat_toolkit::host_lifetime::NativeHostLifetime>,
    ) -> Result<
        crate::installed_host::operator_setup::OperatorSetup,
        meerkat_toolkit::host_lifetime::control::HostLifetimeError,
    > {
        use meerkat_toolkit::host_lifetime::control::HostLifetimeError;
        let selected = lifetime.selected_policy();
        let native = selected
            .native_host
            .as_ref()
            .ok_or(HostLifetimeError::Unavailable)?;
        if self.scope.realm != native.realm.to_string()
            || self.scope.owner != selected.deployment.to_string()
            || self.owner.ingress_domain() != &native.ingress_domain
        {
            return Err(HostLifetimeError::WrongOwner);
        }
        crate::installed_host::operator_setup::OperatorSetup::from_local_gateway(
            lifetime,
            self.store.clone(),
            self.owner.clone(),
        )
    }

    /// Trusted installed application operator over this same canonical owner.
    pub(crate) fn application_operator_setup(
        &self,
        lifetime: Arc<meerkat_toolkit::host_lifetime::NativeHostLifetime>,
    ) -> Result<
        crate::installed_host::operator_setup::OperatorSetup,
        meerkat_toolkit::host_lifetime::control::HostLifetimeError,
    > {
        use meerkat_toolkit::host_lifetime::control::HostLifetimeError;
        let selected = lifetime.selected_policy();
        let native = selected
            .native_host
            .as_ref()
            .ok_or(HostLifetimeError::Unavailable)?;
        if self.scope.realm != native.realm.to_string()
            || self.scope.owner != selected.deployment.to_string()
            || self.owner.ingress_domain() != &native.ingress_domain
        {
            return Err(HostLifetimeError::WrongOwner);
        }
        crate::installed_host::operator_setup::OperatorSetup::from_application_gateway(
            lifetime,
            self.store.clone(),
            self.owner.clone(),
        )
    }

    /// The installed issuer is selected independently of the approving human.
    /// Local-only composition uses its stock operator; an installed application
    /// uses the exact configured remote operator over these same owners.
    pub(crate) fn service_operator_setup(
        &self, lifetime: Arc<meerkat_toolkit::host_lifetime::NativeHostLifetime>,
    ) -> Result<crate::installed_host::operator_setup::OperatorSetup,
        meerkat_toolkit::host_lifetime::control::HostLifetimeError>
    {
        if lifetime.selected_policy().native_host.as_ref()
            .and_then(|host| host.remote_operator.as_ref()).is_some() {
            self.application_operator_setup(lifetime)
        } else { self.local_operator_setup(lifetime) }
    }

    pub async fn new(
        scope: StoreScope,
        store: Arc<dyn ToolkitStore>,
        owner: Arc<ToolkitOriginalOwner>,
        routes: Vec<PrivateOriginalRoute>,
    ) -> Result<Self, PrivateOriginalError> {
        let value = Self::prepare(scope, store, owner).await?;
        value.finalize_routes(routes)?;
        Ok(value)
    }

    /// Retain the actual source owner before native held construction. No
    /// route is usable until its final parent selections are bound once.
    pub(crate) async fn prepare(
        scope: StoreScope,
        store: Arc<dyn ToolkitStore>,
        owner: Arc<ToolkitOriginalOwner>,
    ) -> Result<Self, PrivateOriginalError> {
        scope.validate().map_err(|_| PrivateOriginalError::Denied)?;
        store.capabilities().require_durable_contract()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let value = Self {
            scope,
            store,
            owner,
            routes: OnceLock::new(),
            retained: Mutex::new(Vec::new()),
            helper_sources: Mutex::new(Vec::new()),
            machine: OnceLock::new(),
            identity_runtime: OnceLock::new(),
            controller_pin_source: OnceLock::new(),
            host_lifetime: OnceLock::new(),
            installation_readback: OnceLock::new(),
            service_tool_policy: OnceLock::new(),
        };
        // The host holds its existing store/lifetime exclusion while opening.
        // Audit once before exposing this adapter; no per-event scope scan.
        value.validate_source_format().await?;
        Ok(value)
    }

    /// Only the same Rust preparation owner installs these derived facts.
    /// Validation precedes publication; neither a retry nor another owner may
    /// replace routes already used by this source adapter.
    pub(crate) fn finalize_routes(&self, routes: Vec<PrivateOriginalRoute>)
        -> Result<(), PrivateOriginalError>
    {
        for (index, route) in routes.iter().enumerate() {
            if [
                &route.grant_caller,
                &route.requester,
                &route.ingress_actor,
                &route.logical_executor,
                &route.source_authority,
                &route.authentication_domain.authority,
                &route.event_domain.authority,
            ]
            .iter()
            .any(|principal| principal.validate_qualified().is_err())
                || route
                    .represented_subject
                    .as_ref()
                    .is_some_and(|principal| principal.validate_qualified().is_err())
                || route.realm.to_string() != self.scope.realm
                || routes[..index].iter().any(|other| other.id == route.id)
            {
                return Err(PrivateOriginalError::Denied);
            }
        }
        self.routes.set(routes).map_err(|_| PrivateOriginalError::Denied)
    }

    pub(crate) fn routes(&self) -> Result<&[PrivateOriginalRoute], PrivateOriginalError> {
        self.routes.get().map(Vec::as_slice).ok_or(PrivateOriginalError::Unavailable)
    }

    async fn validate_source_format(&self) -> Result<(), PrivateOriginalError> {
        let mut after = None;
        loop {
            let rows = self
                .store
                .list_records(&self.scope, after.as_deref(), 256)
                .await
                .map_err(store_error)?;
            if rows.is_empty() {
                return Ok(());
            }
            for row in &rows {
                if row.data.schema == SOURCE_SCHEMA {
                    self.decode_stored(row)?;
                }
            }
            let last = rows.last().ok_or(PrivateOriginalError::Unavailable)?;
            if after
                .as_ref()
                .is_some_and(|prior: &String| prior >= &last.key.id)
            {
                return Err(PrivateOriginalError::Unavailable);
            }
            after = Some(last.key.id.clone());
        }
    }

    /// Called once by the native gateway composition with the exact machine
    /// constructed using this source owner's configuration. No wire API can
    /// attach another machine or supply a runtime identity.
    pub(crate) fn bind_machine(
        &self,
        machine: Arc<MeerkatMachine>,
    ) -> Result<(), PrivateOriginalError> {
        self.machine
            .set(Arc::downgrade(&machine))
            .map_err(|_| PrivateOriginalError::Denied)
    }

    /// Native authorization retains this adapter through its policy owner.
    /// The reverse link must not extend the machine or its store lifetime.
    /// Later native binding uses this exact live owner or reports unavailable.
    pub(crate) fn machine(&self) -> Result<Arc<MeerkatMachine>, PrivateOriginalError> {
        self.machine
            .get()
            .and_then(Weak::upgrade)
            .ok_or(PrivateOriginalError::Unavailable)
    }

    pub(crate) fn configuration<P>(
        &self,
        policy: Arc<P>,
    ) -> meerkat_runtime::meerkat_machine::NativeGrantWorkConfiguration
    where
        P: meerkat_runtime::meerkat_machine::ScopedMandateOwner
            + meerkat_authorization::grant_policy::AdmittedWorkPolicyOwner
            + meerkat_authorization::grant_policy::OperationPolicyOwner
            + meerkat_runtime::meerkat_machine::RetainedInvocationOwner
            + 'static,
    {
        let retained = self.owner.retained_resume_check(policy.clone());
        self.owner.configuration(
            meerkat_runtime::meerkat_machine::ScopedInvocation::from_policy(policy.clone()),
            policy,
            Some(retained),
        )
    }

    fn route(&self, id: &Id) -> Result<&PrivateOriginalRoute, PrivateOriginalError> {
        self.routes()?
            .iter()
            .find(|route| &route.id == id)
            .ok_or(PrivateOriginalError::Denied)
    }

    fn key(&self, reference: &PrivateOriginalRef) -> Result<StoreKey, PrivateOriginalError> {
        let route = self.route(&reference.route)?;
        Ok(StoreKey {
            realm: self.scope.realm.clone(),
            owner: self.scope.owner.clone(),
            id: source_key_id(
                &route.realm,
                self.owner.ingress_domain(),
                &route.source_authority,
                &reference.original,
            )?,
        })
    }

    /// Retain one durable row per native original. The first exact event and
    /// its qualified source facts remain immutable. Equivalent route aliases
    /// project references to that row; changed source/content is a conflict.
    /// No grant or native admission is produced here.
    pub async fn retain_event(
        &self,
        event: PrivateAuthenticatedEvent,
    ) -> Result<PrivateOriginalRef, PrivateOriginalError> {
        let route = self.route(&event.route)?;
        let source = SourceFacts::from_route(route, self.owner.ingress_domain());
        if event.contributors.len() > 64
            || !valid_digest(&event.content_sha256)
            || !valid_digest(&event.original_authentication.sha256)
            || !valid_digest(&event.root_event.sha256)
        {
            return Err(PrivateOriginalError::Denied);
        }
        let event_sha256 =
            digest(&canonical_json(&event).map_err(|_| PrivateOriginalError::Denied)?);
        let reference = PrivateOriginalRef {
            route: event.route.clone(),
            original: event.original.clone(),
            event_sha256,
        };
        let key = self.key(&reference)?;
        let data = encode(SourceRecord {
            shared_preparations: Vec::new(),
            setup_request: None,
            configured_setup: None,
            service_setup_children: vec![],
            source,
            event,
            final_association: None,
            operation_cancelled: false,
            service_attachment_failure: None,
            service_attachment_observation: None,
            service_attachment_member: None,
            approved_task: None,
            service_admission: None,
            bound_service_input: None,
            planning_source_evidence: None,
        })?;
        // An existing final binding changes the record, but not the original
        // admission payload. The store compares that frozen initial request.
        let admitted = self
            .store
            .admit(AdmissionRequest {
                key: key.clone(),
                admission_key: key.id.clone(),
                data,
                events: vec![],
                effects: vec![],
            })
            .await;
        match admitted {
            Ok(record) => {
                self.decode_record(record.record(), &reference)?;
            }
            Err(
                toolkit_store::StoreError::AdmissionConflict
                | toolkit_store::StoreError::AlreadyExists,
            ) => {
                // A concurrent first route or an equivalent alias may have won
                // this exact native key. Only its full immutable facts can
                // establish equivalence; a collision is never blind success.
                let record = self
                    .store
                    .get(&key)
                    .await
                    .map_err(store_error)?
                    .ok_or(PrivateOriginalError::Unavailable)?;
                self.decode_record(&record, &reference)?;
            }
            Err(error) => return Err(store_error(error)),
        }
        Ok(reference)
    }

    fn decode_stored(&self, stored: &StoredRecord) -> Result<SourceRecord, PrivateOriginalError> {
        let value = decode_source_record(stored)?;
        if stored.key.scope() != self.scope || value.source.ingress != *self.owner.ingress_domain()
        {
            return Err(PrivateOriginalError::Conflict);
        }
        Ok(value)
    }

    fn decode_record(
        &self,
        stored: &StoredRecord,
        reference: &PrivateOriginalRef,
    ) -> Result<SourceRecord, PrivateOriginalError> {
        let value = self.decode_stored(stored)?;
        let route = self.route(&reference.route)?;
        let mut projected = value.event.clone();
        projected.route = reference.route.clone();
        if stored.key != self.key(reference)?
            || value.source != SourceFacts::from_route(route, self.owner.ingress_domain())
            || projected.original != reference.original
            || digest(&canonical_json(&projected).map_err(|_| PrivateOriginalError::Conflict)?)
                != reference.event_sha256
        {
            return Err(PrivateOriginalError::Conflict);
        }
        if let Some(association) = &value.final_association {
            self.check_source_binding(&value, association)
                .map_err(|_| PrivateOriginalError::Conflict)?;
        }
        Ok(value)
    }

    /// Read immutable source facts for the native binder. This observation is
    /// not contributor custody, current policy or an admission/replay answer.
    pub async fn event(
        &self,
        reference: &PrivateOriginalRef,
    ) -> Result<PrivateAuthenticatedEvent, PrivateOriginalError> {
        let stored = self
            .store
            .get(&self.key(reference)?)
            .await
            .map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        let mut event = self.decode_record(&stored, reference)?.event;
        event.route = reference.route.clone();
        Ok(event)
    }

    /// Return this owner's canonical historical record locator for an exact
    /// retained reference, including equivalent route aliases and cancelled
    /// rows. A missing or mismatched row in this owner's scope is refused.
    ///
    /// Use this locator for `SetupWorkflowTerms::planning_source`; callers must
    /// not reproduce the private key layout. It supplies no current source
    /// authority, grant, member reservation or native admission evidence.
    pub async fn source_record_key(
        &self,
        reference: &PrivateOriginalRef,
    ) -> Result<StoreKey, PrivateOriginalError> {
        let stored = self
            .store
            .get(&self.key(reference)?)
            .await
            .map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        self.decode_record(&stored, reference)?;
        Ok(stored.key)
    }

    /// Historical binding for explicit authenticated restore/replay. Reading
    /// this value cannot reconstruct source custody or an accepted InputId.
    pub async fn binding_evidence(
        &self,
        reference: &PrivateOriginalRef,
    ) -> Result<
        Option<meerkat_authorization_contracts::work_association::InputAuthorityAssociation>,
        PrivateOriginalError,
    > {
        let stored = self
            .store
            .get(&self.key(reference)?)
            .await
            .map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        Ok(self.decode_record(&stored, reference)?.final_association)
    }

    /// The original writer calls this as its durable callback, before it
    /// returns or publishes the final association. Only the first binding may
    /// be inserted. A lost/uncertain response is resolved by reading this exact
    /// row before any new child issuance; no opaque native store is inspected.
    pub async fn persist_binding(
        &self,
        reference: &PrivateOriginalRef,
        association: &meerkat_authorization_contracts::work_association::InputAuthorityAssociation,
    ) -> Result<Option<Arc<StoredRecord>>, OriginalWriterError> {
        self.persist_or_observe_binding(reference, association, false)
            .await
    }

    /// The existing original writer holds its mutation mutex around this call.
    /// Re-reading here, rather than passing an earlier binding snapshot, makes
    /// a durable cancellation win over any later cold binding publication.
    pub(crate) async fn persist_or_observe_binding(
        &self,
        reference: &PrivateOriginalRef,
        association: &meerkat_authorization_contracts::work_association::InputAuthorityAssociation,
        allow_existing: bool,
    ) -> Result<Option<Arc<StoredRecord>>, OriginalWriterError> {
        self.persist_or_observe_selected_binding(reference, association, allow_existing, None).await
    }

    /// The live planning owner selects its own issued lineage. It cannot enter
    /// through configured setup discovery or a portable association alone.
    pub(super) async fn persist_or_observe_workflow_binding(
        &self,
        reference: &PrivateOriginalRef,
        association: &meerkat_authorization_contracts::work_association::InputAuthorityAssociation,
        planning: &InstalledWorkflowPlanning,
    ) -> Result<Option<Arc<StoredRecord>>, OriginalWriterError> {
        self.persist_or_observe_selected_binding(reference, association, true, Some(planning)).await
    }

    async fn persist_or_observe_selected_binding(
        &self,
        reference: &PrivateOriginalRef,
        association: &meerkat_authorization_contracts::work_association::InputAuthorityAssociation,
        allow_existing: bool,
        planning: Option<&InstalledWorkflowPlanning>,
    ) -> Result<Option<Arc<StoredRecord>>, OriginalWriterError> {
        let key = self
            .key(reference)
            .map_err(|_| OriginalWriterError::WrongOwner)?;
        let stored = self
            .store
            .get(&key)
            .await
            .map_err(|_| OriginalWriterError::Unavailable)?
            .ok_or(OriginalWriterError::Unavailable)?;
        let mut record = self
            .decode_record(&stored, reference)
            .map_err(|_| OriginalWriterError::Conflict)?;
        self.check_source_binding(&record, association)?;
        if let Some(selection) = &record.setup_request {
            let lifetime = self.host_lifetime.get().and_then(Weak::upgrade)
                .ok_or(OriginalWriterError::Unavailable)?;
            // The same canonical approved decision remains exact on replay.
            // Only first binding resolves all newly issued parents; a bound
            // target's currentness belongs to its actual native operation.
            if record.final_association.is_some() && !selection.helper_targets.is_empty() {
                crate::installed_host::operator_setup::validate_retained_setup_selection(
                    &lifetime, &self.owner, self.store.as_ref(), selection,
                ).await
            } else {
                crate::installed_host::operator_setup::validate_setup_selection(
                    &lifetime, &self.owner, self.store.as_ref(), selection,
                ).await
            }.map_err(|_| OriginalWriterError::Unavailable)?;
        }
        match planning {
            Some(planning) => planning.check_persistence_binding(self, reference, &record, association)?,
            None => self.check_configured_setup_binding(reference, &record, association)?,
        }
        if self.approved_task_is_cancelled(&record).await
            .map_err(|_| OriginalWriterError::Unavailable)?
        {
            let cancelled = self.persist_source_cancellation(Arc::new(stored)).await?;
            // No first binding may be published after parent cancellation.
            if record.final_association.is_none() {
                return Err(OriginalWriterError::OperationCancelled);
            }
            return Ok(Some(cancelled));
        }
        if let Some(saved) = &record.final_association {
            return if allow_existing && saved == association {
                Ok(record.operation_cancelled.then(|| Arc::new(stored)))
            } else {
                Err(OriginalWriterError::Conflict)
            };
        }
        if record.operation_cancelled {
            // Cancellation before initial binding never creates a fresh source
            // association or task authority on its later replay.
            return Err(OriginalWriterError::OperationCancelled);
        }
        record.final_association = Some(association.clone());
        let data = encode(record).map_err(|_| OriginalWriterError::Conflict)?;
        self.store
            .compare_and_swap(Transition {
                key,
                expected_revision: stored.revision,
                expected_digest: Some(stored.content_digest),
                claim: None,
                data,
                events: vec![],
                effects: vec![],
            })
            .await
            .map_err(|_| OriginalWriterError::Unavailable)?;
        Ok(None)
    }

    fn check_source_binding(
        &self,
        record: &SourceRecord,
        association: &meerkat_authorization_contracts::work_association::InputAuthorityAssociation,
    ) -> Result<(), OriginalWriterError> {
        let c = association.candidate();
        self.check_setup_source_binding(record, association)?;
        planning_source_evidence::check_binding(record, association)
            .map_err(|_| OriginalWriterError::Conflict)?;
        let route = &record.source;
        let evidence_matches =
            |actual: &meerkat_authorization_contracts::evidence::HistoricalEvidenceRef,
             domain: &ResourceDomain,
             expected: &PrivateSourceEvidence| {
                actual.resource.domain == *domain
                    && actual.resource.resource_id == expected.resource_id.as_str()
                    && actual.revision == expected.revision
                    && actual
                        .digest
                        .bytes()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                        == expected.sha256
            };
        if c.original_work.work != record.event.original
            || c.ingress_namespace.occurrence_scope != record.event.occurrence
            || c.ingress_namespace.realm != route.realm
            || c.ingress_namespace.ingress != route.ingress
            || c.requester != route.requester
            || c.ingress_actor != route.ingress_actor
            || c.represented_subject != route.represented_subject
            || c.logical_executor != route.logical_executor
            || c.original_work.authority != route.source_authority
            || !evidence_matches(
                &c.original_authentication,
                &route.authentication_domain,
                &record.event.original_authentication,
            )
            || !evidence_matches(&c.root_event, &route.event_domain, &record.event.root_event)
            || c.contributing_work.len() != record.event.contributors.len()
            || c.contributing_work
                .iter()
                .zip(&record.event.contributors)
                .any(|(actual, expected)| {
                    actual.authority != route.source_authority || &actual.work != expected
                })
        {
            return Err(OriginalWriterError::WrongOwner);
        }
        Ok(())
    }

    /// Read-only consistency check under the original owner's existing writer
    /// mutex. Equivalent route aliases keep the same canonical native identity;
    /// an incompatible valid event cannot replace its binding or cancel fact.
    async fn validate_cancellation_source(
        &self,
        reference: &PrivateOriginalRef,
        binding: Option<
            &meerkat_authorization_contracts::work_association::InputAuthorityAssociation,
        >,
        prior_source: Option<&StoredRecord>,
    ) -> Result<Arc<StoredRecord>, OriginalWriterError> {
        let key = self
            .key(reference)
            .map_err(|_| OriginalWriterError::WrongOwner)?;
        let stored = self
            .store
            .get(&key)
            .await
            .map_err(|_| OriginalWriterError::Unavailable)?
            .ok_or(OriginalWriterError::Unavailable)?;
        let record = self
            .decode_record(&stored, reference)
            .map_err(|_| OriginalWriterError::Conflict)?;
        if let Some(saved) = &record.final_association {
            self.check_source_binding(&record, saved)
                .map_err(|_| OriginalWriterError::Conflict)?;
        }
        if let Some(binding) = binding {
            self.check_source_binding(&record, binding)
                .map_err(|_| OriginalWriterError::Conflict)?;
            if record
                .final_association
                .as_ref()
                .is_some_and(|saved| saved != binding)
            {
                return Err(OriginalWriterError::Conflict);
            }
        }
        if let Some(prior) = prior_source {
            let prior = self
                .decode_stored(prior)
                .map_err(|_| OriginalWriterError::Conflict)?;
            if record.event != prior.event || record.source != prior.source {
                return Err(OriginalWriterError::Conflict);
            }
        }
        Ok(Arc::new(stored))
    }

    /// Retain cancellation in the existing source row. The source owner's
    /// native disposition callback observes this publication. This primitive
    /// does not stop a run and remains internal to the fenced host entry.
    pub(crate) async fn record_operation_cancelled(
        &self,
        reference: &PrivateOriginalRef,
    ) -> Result<(), PrivateOriginalError> {
        self.record_task_group_cancelled(reference).await
    }

    /// Called only after the actual host lifetime has admitted this request.
    /// The private channel retains this future in its existing JoinSet through
    /// caller loss. A dropped direct Rust future instead leaves uncertain
    /// persistence Pending until this exact cancellation is reconciled.
    pub(crate) async fn cancel_original_operation(
        &self,
        reference: &PrivateOriginalRef,
    ) -> Result<PrivateOriginalCancellation, PrivateOriginalError> {
        let cancelled = self.record_cancelled_source_set(reference, None, None, None).await?;
        // Source cancellation and existing physical preparation leave have
        // completed. The outer channel retains this follow-on work through
        // caller loss; no initial native binder waits for workflow close.
        self.depart_cancelled_workflows(&cancelled).await
    }

    /// Attach only the actual source owner's returned handle, after its durable
    /// callback succeeded. This never marks the original admitted. Source
    /// custody is promoted only by actual native submission settlement or the
    /// admitted-original observation callback, neither of which permits replay.
    pub async fn hold_binding(
        &self,
        reference: PrivateOriginalRef,
        original: Arc<RetainedToolkitOriginal>,
    ) -> Result<(), PrivateOriginalError> {
        self.hold_binding_with_mcp(reference, original, Vec::new()).await
    }

    async fn hold_binding_with_mcp(
        &self,
        reference: PrivateOriginalRef,
        original: Arc<RetainedToolkitOriginal>,
        service_mcp: Vec<service_grants::RetainedServiceMcpAccess>,
    ) -> Result<(), PrivateOriginalError> {
        let stored = self
            .store
            .get(&self.key(&reference)?)
            .await
            .map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        let record = self.decode_record(&stored, &reference)?;
        if record.final_association.as_ref() != Some(original.association()) {
            return Err(PrivateOriginalError::Conflict);
        }
        let retain_bound_input = record.planning_source_evidence.is_some()
            || record.approved_task.is_some()
            || self.stock_setup_source(&record, &reference)?;
        let mut retained = self
            .retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        if let Some(previous) = retained.iter().find(|held| held.reference == reference) {
            return if Arc::ptr_eq(&previous.original, &original) && previous.service_mcp == service_mcp {
                Ok(())
            } else {
                Err(PrivateOriginalError::Conflict)
            };
        }
        if retained
            .iter()
            .any(|previous| previous.original.association() == original.association())
        {
            return Err(PrivateOriginalError::Conflict);
        }
        retained.push(Arc::new(HeldPrivateOriginal {
            reference,
            original,
            service_mcp,
            retain_bound_input,
            console_login: OnceLock::new(),
            unresolved: Mutex::new(Vec::new()),
            service_attachments: Mutex::new(Vec::new()),
            shared_preparations: Mutex::new(Vec::new()),
            setup_workflow: OnceLock::new(),
            workflow_selections: Mutex::new(Vec::new()),
            workflow_plans: Mutex::new(Vec::new()),
        }));
        Ok(())
    }

    /// Exact in-process association-to-route correspondence from the writer's
    /// retained handle. This is not admission or a current grant decision. The
    /// native source/grant owners independently check both at their boundary.
    pub(crate) fn route_for_binding(
        &self,
        association: &meerkat_authorization_contracts::work_association::InputAuthorityAssociation,
    ) -> Result<Id, PrivateOriginalError> {
        self.retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .iter()
            .find(|held| held.original.association() == association)
            .map(|held| held.reference.route.clone())
            .ok_or(PrivateOriginalError::Unavailable)
    }

    /// Revoke this writer's own original-specific operation child under actual
    /// native controller custody. The caller cannot name a grant or principal.
    /// Cold binding reconstruction is an explicit authenticated writer action;
    /// a decoded row alone is not enough to cancel or authorize anything.
    pub fn revoke_original_operation_grant(
        &self,
        reference: &PrivateOriginalRef,
    ) -> Result<PrivateOriginalCancellation, PrivateOriginalError> {
        let route = self.route(&reference.route)?;
        let machine = self.machine()?;
        let original = self
            .retained
            .lock()
            .map_err(|_| PrivateOriginalError::Unavailable)?
            .iter()
            .find(|held| &held.reference == reference)
            .map(|held| held.original.clone())
            .ok_or(PrivateOriginalError::Unavailable)?;
        let mut custody = machine
            .try_controller_grant_mutation()
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        self.owner
            .cancel_original(&original, &route.grant_caller, &mut custody)
            .map_err(|error| match error {
                OriginalWriterError::Grant(meerkat_authorization::grants::GrantRefusal::Denied) => {
                    PrivateOriginalError::Denied
                }
                _ => PrivateOriginalError::Unavailable,
            })?;
        Ok(PrivateOriginalCancellation::OperationGrantRevoked)
    }
}

/// Project the exact validated Toolkit row under the source owner's existing
/// qualified ingress domain. This is a historical coordinate, not the parent
/// application's root-event evidence or an additional permission owner. The
/// writer has already checked the selected StoreScope and canonical source key;
/// retain the entire key so realm/deployment rows cannot alias in this domain.
/// No store read, clock, native grant lookup or publication mutation occurs here.
pub(crate) fn cancellation_evidence(
    stored: &StoredRecord,
    namespace: &meerkat_authorization_contracts::work_association::QualifiedIngressNamespace,
    original: &meerkat_authorization_contracts::work_association::OriginalWorkRef,
) -> Result<meerkat_authorization_contracts::evidence::HistoricalEvidenceRef, PrivateOriginalError>
{
    use meerkat_authorization_contracts::{
        evidence::{EvidenceDigest, HistoricalEvidenceRef},
        resource::ResourceRef,
    };
    let record = decode_source_record(stored)?;
    if !record.operation_cancelled
        || record.source.realm != namespace.realm
        || record.source.ingress != namespace.ingress
        || record.source.source_authority != original.authority
        || record.event.original != original.work
        || record
            .final_association
            .as_ref()
            .is_some_and(|association| {
                let claims = association.candidate();
                claims.original_work != *original
                    || claims.ingress_namespace.realm != namespace.realm
                    || claims.ingress_namespace.ingress != namespace.ingress
            })
    {
        return Err(PrivateOriginalError::Conflict);
    }
    let mut digest_bytes = [0; 32];
    for (index, byte) in digest_bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&stored.content_digest[index * 2..index * 2 + 2], 16)
            .map_err(|_| PrivateOriginalError::Conflict)?;
    }
    let coordinate = canonical_json(&serde_json::json!({
        "schema": stored.data.schema,
        "key": stored.key,
    }))
    .map_err(|_| PrivateOriginalError::Conflict)?;
    Ok(HistoricalEvidenceRef {
        resource: ResourceRef {
            domain: namespace.ingress.clone(),
            resource_id: String::from_utf8(coordinate)
                .map_err(|_| PrivateOriginalError::Conflict)?,
        },
        revision: EvidenceId::new(stored.revision.to_string())
            .map_err(|_| PrivateOriginalError::Conflict)?,
        digest: EvidenceDigest::from_array(digest_bytes),
    })
}

pub(crate) fn source_key_id(
    realm: &RealmId,
    ingress: &ResourceDomain,
    authority: &PrincipalRef,
    work: &EvidenceId,
) -> Result<String, PrivateOriginalError> {
    let original = meerkat_authorization_contracts::work_association::OriginalWorkRef {
        authority: authority.clone(),
        work: work.clone(),
    };
    Ok(digest(
        &canonical_json(&(SOURCE_SCHEMA, realm, ingress, original))
            .map_err(|_| PrivateOriginalError::Conflict)?,
    ))
}

fn decode_source_record(stored: &StoredRecord) -> Result<SourceRecord, PrivateOriginalError> {
    if stored.key.validate().is_err()
        || stored.revision == 0
        || stored.data.schema != SOURCE_SCHEMA
        || stored.data.version != SOURCE_VERSION
        || stored.data.digest().ok().as_deref() != Some(stored.content_digest.as_str())
        || !valid_digest(&stored.content_digest)
    {
        return Err(PrivateOriginalError::Conflict);
    }
    let value: SourceRecord = serde_json::from_value(stored.data.body.clone())
        .map_err(|_| PrivateOriginalError::Conflict)?;
    value.source.validate()?;
    if stored.key.realm != value.source.realm.to_string()
        || stored.key.id
            != source_key_id(
                &value.source.realm,
                &value.source.ingress,
                &value.source.source_authority,
                &value.event.original,
            )?
        || value.event.contributors.len() > 64
        || !valid_digest(&value.event.content_sha256)
        || !valid_digest(&value.event.original_authentication.sha256)
        || !valid_digest(&value.event.root_event.sha256)
        || canonical_json(&value).map_err(|_| PrivateOriginalError::Conflict)?
            != canonical_json(&stored.data.body).map_err(|_| PrivateOriginalError::Conflict)?
    {
        return Err(PrivateOriginalError::Conflict);
    }
    planning_source_evidence::validate(&value)?;
    cold_service_admission::validate_retained_input(&value)?;
    configured_setup::service::ServiceSetupChildObservation::validate_set(&value)?;
    if let Some(task) = &value.approved_task { task.validate()?; }
    if let Some(member) = &value.service_attachment_member {
        if value.service_attachment_failure.is_none() || !value.operation_cancelled
            || !matches!(&value.approved_task, Some(service_approved_input::ApprovedTaskLink::Batch(batch))
                if batch.members.iter().any(|selected| &selected.grant == member)) {
            return Err(PrivateOriginalError::Conflict);
        }
    }
    if value.service_attachment_observation.is_some() && value.service_attachment_failure.is_none()
    {
        return Err(PrivateOriginalError::Conflict);
    }
    if value.service_attachment_failure.is_some()
        && (!value.operation_cancelled || value.approved_task.is_none()
            || value.final_association.is_some() || value.service_admission.is_some())
    { return Err(PrivateOriginalError::Conflict); }
    Ok(value)
}

fn encode(record: SourceRecord) -> Result<RecordData, PrivateOriginalError> {
    Ok(RecordData {
        schema: SOURCE_SCHEMA.into(),
        version: SOURCE_VERSION,
        body: serde_json::to_value(record).map_err(|_| PrivateOriginalError::Conflict)?,
    })
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}
fn store_error(error: toolkit_store::StoreError) -> PrivateOriginalError {
    match error {
        toolkit_store::StoreError::AdmissionConflict
        | toolkit_store::StoreError::AlreadyExists
        | toolkit_store::StoreError::Conflict => PrivateOriginalError::Conflict,
        _ => PrivateOriginalError::Unavailable,
    }
}
