//! Explicit live host composition over the normal native per-helper adapters.

use super::*;
use crate::{
    application_setup::resource::{SetupResourceProvider, SetupResourceSelection},
    resources::{SharedSetupCallContext, SharedSetupPeer},
    setup::PreparedSetupHelper,
};
use meerkat_core::ToolConsequencePolicyRegistry;
use meerkat_mob::MemberRuntimeRegistrationHook;
use meerkat_runtime::meerkat_machine::NativeGrantWorkConfiguration;
use toolkit_mobkit::installed_host::{
    PreparedInstallationOwner, acquisition::InstalledServiceTaskSource,
    prepared_registration::PreparedMemberRegistration,
};

/// One resource-produced peer and its ordinary protected software decision
/// owner. The host retains the corresponding shared resource owner until all
/// native helpers and entered work have joined. This is not a saved peer map.
pub struct SharedSetupInstallation {
    pub helper: PreparedSetupHelper,
    pub peer: SharedSetupPeer,
    pub approvals: LocalApprovals,
}

/// Prepare the complete shared setup composition from the actual installation
/// owner, after any helper-role projection and before consuming that owner.
/// Each live peer is joined to its final helper and the owner's exact roster.
/// No serialized configuration alone selects configured attachment authority.
///
/// Bind the native configuration next, use its registration for both native
/// construction and installed adoption, then consume the bound composition to
/// configure the factory with the gateway participant's service task source.
/// Retain and join the shared resource owner after native helpers have closed.
pub fn prepare_shared_setup_installation(
    owner: &PreparedInstallationOwner,
    realm: RealmLocator,
    selections: Vec<SharedSetupInstallation>,
    delegate: Arc<dyn meerkat_mcp::McpCallContextProvider>,
) -> Result<PreparedSharedSetupInstallation, ConnectError> {
    if owner.selected().native_host.realm != realm.realm {
        return Err(refused(
            "Shared setup realm differs from the installation owner",
        ));
    }
    let factory = SharedSetupFactory::prepare(realm, selections, delegate)?;
    let resources = factory
        .entries
        .iter()
        .map(|entry| {
            SetupResourceSelection::from_shared(owner, entry.helper.clone(), entry.context.clone())
                .map(Arc::new)
                .map_err(|_| refused("Shared setup resource is not selected by this owner"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PreparedSharedSetupInstallation { factory, resources })
}

/// A single-use preparation retaining the resource and registration participants.
/// This does not own native sessions or the shared Controller process.
pub struct PreparedSharedSetupInstallation {
    factory: SharedSetupFactory,
    resources: Vec<Arc<SetupResourceSelection>>,
}
impl PreparedSharedSetupInstallation {
    /// Bind configured attachment and selected destination together. The
    /// existing member hook and policy registry remain the native owners.
    /// Pass the configuration taken from the same pending installed host and
    /// the hook that prepares that owner's selected members.
    pub fn bind_native(
        self,
        mut configuration: NativeGrantWorkConfiguration,
        preparation: Arc<dyn MemberRuntimeRegistrationHook>,
        registry: Arc<ToolConsequencePolicyRegistry>,
    ) -> BoundSharedSetupInstallation {
        configuration.configured_mcp_attachment = Some(Arc::new(SetupResourceProvider::multiple(
            self.resources.clone(),
            configuration.configured_mcp_attachment.take(),
        )));
        let resources = self.resources;
        let registration = Arc::new(PreparedMemberRegistration::new(
            preparation,
            registry,
            Arc::new(move |identity, destination| {
                for resource in &resources {
                    resource.selected_destination(identity, destination)?;
                }
                Ok(())
            }),
        ));
        BoundSharedSetupInstallation {
            factory: self.factory,
            configuration,
            registration,
        }
    }
}

/// The same native configuration and destination participant, retained until
/// the factory's task source is available. Neither half is configured separately.
pub struct BoundSharedSetupInstallation {
    factory: SharedSetupFactory,
    configuration: NativeGrantWorkConfiguration,
    registration: Arc<PreparedMemberRegistration>,
}
impl BoundSharedSetupInstallation {
    /// Supply this exact Arc to gateway_runtime and later installed adoption.
    pub fn registration(&self) -> Arc<PreparedMemberRegistration> {
        self.registration.clone()
    }

    /// Opt into native per-attempt peer retirement using this exact resource
    /// owner. Refuse an existing opaque factory guard installation. The same
    /// provider, destination hook, task source and native policy stay selected.
    /// Retain the resource through native shutdown and its bounded guard joins.
    pub fn configure_factory_with_attempt_guards(
        self,
        factory: AgentFactory,
        tasks: InstalledServiceTaskSource,
        owner: &crate::resources::SharedSetupOwner,
    ) -> Result<(AgentFactory, NativeGrantWorkConfiguration), ConnectError> {
        let contexts: Vec<_> = self
            .factory
            .entries
            .iter()
            .map(|entry| entry.context.clone())
            .collect();
        let factory = owner.install_attempt_guards(factory, &contexts)?;
        Ok(self.configure_factory(factory, tasks))
    }

    /// Consume once before native construction. The returned configuration is
    /// used by that same factory's native persistence/machine composition.
    pub fn configure_factory(
        self,
        factory: AgentFactory,
        tasks: InstalledServiceTaskSource,
    ) -> (AgentFactory, NativeGrantWorkConfiguration) {
        (self.factory.configure(factory, tasks), self.configuration)
    }
}

/// Configure only the factory side of a host that already supplies configured
/// attachment authority and the exact native destination binding for every
/// selected helper. This function is not the complete custom-host setup path;
/// use prepare_shared_setup_installation to bind those participants together.
///
/// Supply the factory's existing call-context provider as `delegate`: every
/// unrelated destination and its business authentication retain that provider.
/// Each helper receives its own native adapter and software decision owner.
/// A rebuild needs a fresh composition and approval owner. This entry adds
/// neither account/public-access tools nor native permission.
pub fn configure_shared_setup_installation(
    factory: AgentFactory,
    realm: RealmLocator,
    selections: Vec<SharedSetupInstallation>,
    tasks: InstalledServiceTaskSource,
    delegate: Arc<dyn meerkat_mcp::McpCallContextProvider>,
) -> Result<AgentFactory, ConnectError> {
    Ok(SharedSetupFactory::prepare(realm, selections, delegate)?.configure(factory, tasks))
}

struct PendingEntry {
    helper: PreparedSetupHelper,
    context: Arc<SharedSetupCallContext>,
    approvals: LocalApprovals,
}
struct SharedSetupFactory {
    realm: RealmLocator,
    entries: Vec<PendingEntry>,
    provider: Arc<dyn meerkat_mcp::McpCallContextProvider>,
}
impl SharedSetupFactory {
    fn prepare(
        realm: RealmLocator,
        selections: Vec<SharedSetupInstallation>,
        delegate: Arc<dyn meerkat_mcp::McpCallContextProvider>,
    ) -> Result<Self, ConnectError> {
        if !(2..=8).contains(&selections.len()) {
            return Err(refused("Select 2-8 actual setup helpers"));
        }
        let mut members = std::collections::BTreeSet::new();
        let mut servers = std::collections::BTreeSet::new();
        let mut provider = delegate;
        let mut entries = Vec::with_capacity(selections.len());
        for selection in selections {
            let member = selection.helper.member();
            member
                .comms_name()
                .map_err(|_| refused("Invalid selected setup helper"))?;
            if meerkat_core::mob_realm_id(&member.mob_id).as_ref().ok() != Some(&realm.realm)
                || !members.insert((member.mob_id.clone(), member.member.clone()))
                || !servers.insert(
                    toolkit_package::canonical_json(selection.helper.server())
                        .map_err(|_| refused("Invalid prepared setup configuration"))?,
                )
            {
                return Err(refused(
                    "Setup helpers must have distinct exact native destinations",
                ));
            }
            let context = SharedSetupCallContext::new(selection.peer, &selection.helper, provider)?;
            provider = context.clone();
            entries.push(PendingEntry {
                helper: selection.helper,
                context,
                approvals: selection.approvals,
            });
        }
        Ok(Self {
            realm,
            entries,
            provider,
        })
    }

    fn configure(self, factory: AgentFactory, tasks: InstalledServiceTaskSource) -> AgentFactory {
        let entries = self
            .entries
            .into_iter()
            .map(|entry| Entry {
                member: entry.helper.member().clone(),
                context: entry.context,
                approvals: Arc::new(entry.approvals.with_service_tasks(Some(tasks.clone()))),
            })
            .collect();
        factory
            .mcp_call_context_provider(self.provider)
            .with_mcp_adapter_composer(Arc::new(SharedComposer {
                realm: self.realm,
                entries,
            }))
    }
}

struct Entry {
    member: MobMemberBinding,
    context: Arc<SharedSetupCallContext>,
    approvals: Arc<LocalApprovals>,
}
struct SharedComposer {
    realm: RealmLocator,
    entries: Vec<Entry>,
}
impl McpAdapterComposer for SharedComposer {
    fn compose(
        &self,
        adapter: &Arc<McpRouterAdapter>,
        session: &SessionId,
        member: Option<&MobMemberBinding>,
    ) -> Result<Arc<dyn AgentToolDispatcher>, McpAdapterComposeRefusal> {
        for entry in &self.entries {
            if !selected_member(&entry.member, member)? {
                continue;
            }
            entry
                .approvals
                .bind_session(session)
                .map_err(|_| composition_refused())?;
            let checked = crate::service_install::CheckedInstalls::with_shared_software_review(
                adapter.clone(),
                entry.approvals.clone(),
                entry.context.clone(),
            );
            checked
                .bind_realm(&self.realm)
                .map_err(|_| composition_refused())?;
            return Ok(checked);
        }
        Ok(adapter.clone())
    }
}
