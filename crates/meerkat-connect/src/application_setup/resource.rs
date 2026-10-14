//! The exact trusted setup resource joined to each native construction.
//!
//! Fresh compilation and ordinary completed-bundle startup use this same
//! participant. Native owns registration lifetime and canonical bindings.

use super::*;
use meerkat_core::{SessionId, mcp_attachment::{ConfiguredMcpAttachmentAuthority, McpAttachmentRefusal}};
use meerkat_mob::{MemberDestinationSelection, MemberRuntimeBuildIdentity, MobError};
use meerkat_runtime::meerkat_machine::{AgentBindingUnavailable, ConfiguredMcpAttachmentProvider, SessionAgentBinding};
use std::{collections::BTreeMap, sync::{Arc, Mutex, OnceLock, Weak}};

enum ResourceProjection {
    Preparing {
        helper: MobMemberBinding,
        source: MobMemberBinding,
        profile: ApplicationSetupProfile,
        tools: ApplicationSetupTools,
        resources: PreparedApplicationResources,
    },
    Completed(PreparedApplicationSetup),
}

pub(crate) struct SetupResourceSelection {
    helper: MobMemberBinding,
    members: Vec<compilation::ApplicationMemberSelection>,
    server: McpServerConfig,
    projection: ResourceProjection,
    // Only pending construction correlation. Native authorities own the strong
    // participant; selected and abandoned constructions are not retained here.
    pub(super) registration_slots: Mutex<BTreeMap<String, Weak<SetupResourceRegistration>>>,
}

pub(crate) struct SetupResourceRegistration {
    pub(super) agent: SessionAgentBinding,
    selected: OnceLock<()>,
}
impl SetupResourceRegistration {
    fn current(&self) -> Result<(), String> {
        self.selected.get().ok_or("resource registration has no selected helper destination")?;
        registration_current(&self.agent)
    }
}

impl SetupResourceSelection {
    pub(super) fn from_preparation(
        input: &compilation::ApplicationSetupCompilationInput,
        source: MobMemberBinding,
        resources: PreparedApplicationResources,
        server: McpServerConfig,
    ) -> Self {
        Self {
            helper: input.helper.member.clone(), members: input.members.clone(), server,
            projection: ResourceProjection::Preparing {
                helper: input.helper.member.clone(), source, profile: input.helper_profile,
                tools: input.helper_tools, resources,
            },
            registration_slots: Mutex::new(BTreeMap::new()),
        }
    }

    /// The caller has authenticated this exact completed bundle through the
    /// installed host. This method checks its retained resource consistency;
    /// arbitrary serialized configuration never selects a native authority.
    pub(crate) fn from_completed(setup: &PreparedApplicationSetup) -> Result<Self, String> {
        if setup.schema != 4 { return Err("completed setup resource requires schema4".into()); }
        setup.helper_projection()?;
        let owner = setup.native_owner.as_ref().ok_or("completed native owner is absent")?;
        Ok(Self {
            helper: setup.helper.member.clone(), members: owner.native_host.members.clone(),
            server: setup.server.clone(), projection: ResourceProjection::Completed(setup.clone()),
            registration_slots: Mutex::new(BTreeMap::new()),
        })
    }

    pub(crate) fn server(&self) -> &McpServerConfig { &self.server }

    pub(crate) fn helper_projection(&self) -> Result<PreparedSetupHelper, String> {
        match &self.projection {
            ResourceProjection::Completed(setup) => setup.helper_projection(),
            ResourceProjection::Preparing { helper, source, profile, tools, resources } => {
                let bytes = read_regular_artifact(&resources.handoff.path)?;
                if hash(&bytes) != resources.handoff.sha256 {
                    return Err("retained application preparer handoff changed".into());
                }
                let projection = profile.project(
                    PreparedSetupConnection::from_preparer_output(&bytes).map_err(|error| error.to_string())?,
                    source.clone(), *tools,
                ).map_err(|error| error.to_string())?;
                if projection.member() != helper || projection.server() != &self.server {
                    return Err("prepared helper projection changed".into());
                }
                Ok(projection)
            }
        }
    }

    fn retain_registration(&self, session: &SessionId, agent: &SessionAgentBinding)
        -> Result<Arc<SetupResourceRegistration>, String>
    {
        let mut slots = self.registration_slots.lock().map_err(|_| "native registration capture unavailable")?;
        slots.retain(|_, participant| participant.strong_count() != 0);
        let key = session.to_string();
        if let Some(retained) = slots.get(&key).and_then(Weak::upgrade) {
            // The public destination hook does not carry a registration slot.
            // Do not let a replacement steal a still-pending old construction.
            registration_current(&retained.agent)?;
            registration_current(agent)?;
            return Ok(retained);
        }
        if slots.len() >= self.members.len() {
            return Err("pending registrations exceed the selected roster".into());
        }
        registration_current(agent)?;
        let participant = Arc::new(SetupResourceRegistration { agent: agent.clone(), selected: OnceLock::new() });
        slots.insert(key, Arc::downgrade(&participant));
        Ok(participant)
    }

    pub(super) fn select_registration(&self,
        session: &meerkat_authorization_contracts::evidence::EvidenceId, helper: bool,
    ) -> Result<(), String> {
        let participant = self.registration_slots.lock().map_err(|_| "native registration capture unavailable")?
            .remove(session.as_str()).and_then(|participant| participant.upgrade());
        // Existing canonical bindings already retain their selected participant.
        // An absent pending participant grants nothing to a new authority.
        if let Some(participant) = participant {
            registration_current(&participant.agent)?;
            if helper { participant.selected.set(()).map_err(|_| "registration already selected")?; }
        }
        Ok(())
    }

    /// Invoked only after the actual preparation or installed hook accepted
    /// this complete destination. Read-only expected_destination never calls it.
    pub(crate) fn selected_destination(&self, identity: &MemberRuntimeBuildIdentity,
        destination: &MemberDestinationSelection,
    ) -> Result<(), MobError> {
        let realm = meerkat_core::mob_realm_id(&self.helper.mob_id)
            .map_err(|error| MobError::WiringError(error.to_string()))?;
        let member = self.members.iter().find(|row| &row.member == identity.member())
            .ok_or_else(|| MobError::WiringError("resource member is not selected".into()))?;
        let expected = MemberDestinationSelection {
            logical_owner: member.logical_owner.clone(), context: identity.session_document().clone(),
            context_generation: member.context_generation, audience: member.audience.clone(),
        };
        if identity.realm_id() != &realm || destination != &expected {
            return Err(MobError::WiringError("resource destination differs from selected application".into()));
        }
        self.select_registration(identity.session_document(), identity.member() == &self.helper)
            .map_err(MobError::WiringError)
    }
}

pub(crate) struct SetupResourceProvider {
    selection: Arc<SetupResourceSelection>,
    installed: Option<Arc<dyn ConfiguredMcpAttachmentProvider>>,
}
impl SetupResourceProvider {
    pub(crate) fn new(selection: Arc<SetupResourceSelection>, installed: Option<Arc<dyn ConfiguredMcpAttachmentProvider>>) -> Self {
        Self { selection, installed }
    }
}
impl ConfiguredMcpAttachmentProvider for SetupResourceProvider {
    fn configured(&self, session: &SessionId, agent: SessionAgentBinding)
        -> Option<Arc<dyn ConfiguredMcpAttachmentAuthority>>
    {
        let installed = self.installed.as_ref().and_then(|owner| owner.configured(session, agent.clone()));
        let registration = self.selection.retain_registration(session, &agent).ok();
        Some(Arc::new(SetupResourceAuthority { selection: self.selection.clone(), agent, registration, installed }))
    }
    fn agent_selection(&self, agent: SessionAgentBinding) -> Option<Arc<dyn ConfiguredMcpAttachmentAuthority>> {
        self.installed.as_ref().and_then(|owner| owner.agent_selection(agent))
    }
}

struct SetupResourceAuthority {
    selection: Arc<SetupResourceSelection>,
    agent: SessionAgentBinding,
    registration: Option<Arc<SetupResourceRegistration>>,
    installed: Option<Arc<dyn ConfiguredMcpAttachmentAuthority>>,
}
impl ConfiguredMcpAttachmentAuthority for SetupResourceAuthority {
    fn authorize_configured(&self, server: &McpServerConfig) -> Result<(), McpAttachmentRefusal> {
        if server.name != self.selection.server().name {
            return self.installed.as_ref().ok_or(McpAttachmentRefusal::Unavailable)?.authorize_configured(server);
        }
        if server != self.selection.server() { return Err(McpAttachmentRefusal::Mismatch); }
        let registration = self.registration.as_ref().ok_or(McpAttachmentRefusal::NotCurrent)?;
        registration.current().map_err(|_| McpAttachmentRefusal::NotCurrent)?;
        registration_current(&self.agent).map_err(|_| McpAttachmentRefusal::NotCurrent)?;
        let projection = self.selection.helper_projection().map_err(|_| McpAttachmentRefusal::Unavailable)?;
        if projection.server() != server { return Err(McpAttachmentRefusal::Mismatch); }
        registration.current().map_err(|_| McpAttachmentRefusal::NotCurrent)?;
        registration_current(&self.agent).map_err(|_| McpAttachmentRefusal::NotCurrent)
    }
}

fn registration_current(agent: &SessionAgentBinding) -> Result<(), String> {
    match agent.current() {
        Ok(_) | Err(AgentBindingUnavailable::Unbound) => Ok(()),
        Err(AgentBindingUnavailable::Retired) => Err("native registration retired".into()),
    }
}
