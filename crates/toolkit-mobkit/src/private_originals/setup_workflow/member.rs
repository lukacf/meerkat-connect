//! Host-owned fresh-member selection. Use with the existing held full-roster
//! bootstrap; this is not an append operation on an active roster.
use super::*;
use crate::original_ingress::workflow_member::SelectedWorkflowMember;
use meerkat_mobkit::identity_first::{AgentAddressability, DurableAgentSpec, HeldIdentityMember};
use meerkat_toolkit::setup::SetupWorkflowTerms;

/// An opaque restrictive selection owned by this application's canonical
/// workflow/source owner. Native registration and held completion supply the
/// actual session and controller observation. It conveys no planning grant.
/// The host must supply a compiled, fresh, InternalOnly member. Several
/// unrelated workflows may reserve distinct compiled members in the same host.
pub struct InstalledWorkflowMember {
    source: Weak<PrivateOriginals>,
    reference: SetupWorkflowRef,
    original: PrivateOriginalRef,
    member: MobMemberBinding,
}
impl PrivateOriginals {
    // Only the composed gateway reserves before native member creation. The
    // existing source lifetime is selected atomically with its restriction.
    pub(crate) async fn reserve_workflow_member_for_host(
        self: &Arc<Self>, lifetime: &Arc<meerkat_toolkit::host_lifetime::NativeHostLifetime>,
        terms: &SetupWorkflowTerms, original: &PrivateOriginalRef, spec: &DurableAgentSpec,
    ) -> Result<Arc<InstalledWorkflowMember>, PrivateOriginalError> {
        lifetime.validate_current_selection().map_err(|_| PrivateOriginalError::Unavailable)?;
        let selected = lifetime.selected_policy();
        let native = selected.native_host.as_ref().ok_or(PrivateOriginalError::Unavailable)?;
        if self.scope.realm != native.realm.to_string()
            || self.scope.owner != selected.deployment.to_string()
            || self.owner.ingress_domain() != &native.ingress_domain
        { return Err(PrivateOriginalError::Denied); }
        if let Some(bound) = self.host_lifetime.get() {
            let bound = bound.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
            if !Arc::ptr_eq(&bound, lifetime) { return Err(PrivateOriginalError::Denied); }
        }
        let reference = self.workflow_store()?.workflow_ref(terms).map_err(|_| PrivateOriginalError::Conflict)?;
        let route = self.route(&original.route)?;
        let event = self.event(original).await?;
        let compiled = native.routes.iter().find(|row| row.id == original.route).ok_or(PrivateOriginalError::Denied)?;
        let (member, requester, actor) = compiled.source_binding(selected).map_err(|_| PrivateOriginalError::Denied)?;
        if terms.planning_source != self.key(original)? || member != &terms.lead
            || requester != &route.requester || actor != &route.ingress_actor
            || terms.requester != route.requester || terms.realm != route.realm
            || route.grant_target.as_str() != member.member
            || meerkat_mobkit::member_comms_id::mob_member_id(spec.identity.as_str()).as_str() != member.member
            || spec.addressability != AgentAddressability::InternalOnly
            || spec.context.is_some() || spec.initial_message.is_some()
            || spec.binding.is_some() || spec.placement.is_some() || event.contributors.len() != 1
        { return Err(PrivateOriginalError::Denied); }
        self.owner.select_workflow_member(SelectedWorkflowMember {
            reference: reference.clone(), member: member.clone(), realm: route.realm.clone(),
            original: meerkat_authorization_contracts::work_association::OriginalWorkRef {
                authority: route.source_authority.clone(), work: original.original.clone(),
            }, identity: spec.identity.clone(), captured: None,
        }, || lifetime.validate_current_selection().map_err(|_| OriginalWriterError::Unavailable),
        || self.bind_host_lifetime(lifetime).map_err(|error| match error {
            PrivateOriginalError::Unavailable => OriginalWriterError::Unavailable,
            _ => OriginalWriterError::WrongOwner,
        })).await.map_err(custody_error)?;
        Ok(Arc::new(InstalledWorkflowMember {
            source: Arc::downgrade(self),
            reference, original: original.clone(), member: member.clone(),
        }))
    }
}
impl InstalledWorkflowMember {
    /// Compose this participant with the host's existing registration hook.
    /// It observes that hook's actual selection before native installation.
    pub(crate) fn registration_participant(self: &Arc<Self>)
        -> crate::installed_host::prepared_registration::SelectedDestinationParticipant
    {
        let selected = self.clone();
        Arc::new(move |identity, destination| {
            let source = selected.source.upgrade().ok_or_else(|| meerkat_mob::MobError::WiringError(
                "workflow source owner is unavailable".into()))?;
            source.owner.capture_workflow_member(&selected.reference, identity, destination)
                .map_err(|_| meerkat_mob::MobError::WiringError("workflow member selection refused".into()))
        })
    }

    /// Called by the real held full-roster completion callback before release.
    /// The report constrains the later actual native client; it grants nothing.
    pub async fn complete_held_member(&self, held: &HeldIdentityMember) -> Result<(), PrivateOriginalError> {
        let source = self.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?;
        source.owner.finish_workflow_member(&self.reference, held).await.map_err(custody_error)
    }

    /// Exact captured native session, available only after held completion.
    /// This observation is not a live-session or exclusive-run capability.
    pub fn session(&self) -> Result<meerkat_core::SessionId, PrivateOriginalError> {
        self.source.upgrade().ok_or(PrivateOriginalError::Unavailable)?.owner
            .dedicated_workflow_session(&self.reference, &self.member, &self.original.original)
            .map_err(custody_error)?.ok_or(PrivateOriginalError::Unavailable)
    }
}
