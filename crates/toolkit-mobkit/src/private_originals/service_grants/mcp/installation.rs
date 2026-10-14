//! The existing operator record carries the reviewed software configuration.
//! Reopen that exact parent decision, then ask its installed package owner.
use super::*;
use std::sync::Arc;
use crate::private_originals::service_approved_input::attachment::attachment_preparation_diagnostic;

impl PrivateOriginals {
    pub(crate) fn bind_service_installation_readback(
        &self, owner: Arc<dyn ServiceInstallationReadback>,
    ) -> Result<(), PrivateOriginalError> {
        self.installation_readback.set(owner).map_err(|_| PrivateOriginalError::Conflict)
    }

    pub(crate) async fn read_service_installation(
        self: &Arc<Self>, reference: &PrivateOriginalRef,
    ) -> Result<McpServerConfig, PrivateOriginalError> {
        let stored = self.store.get(&self.key(reference)?).await.map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        let record = self.decode_record(&stored, reference)?;
        let task = record.approved_task.as_ref().ok_or(PrivateOriginalError::Denied)?;
        if record.final_association.is_some() || record.service_admission.is_some()
            || !self.service_task_submission_current(&record).await? {
            return Err(PrivateOriginalError::Denied);
        }
        let access_stored = self.store.get(&self.access_key(&task.grant)?).await.map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        let access = self.decode_access(&access_stored, &task.grant)?;
        let AccessDecision::Mcp(decision) = &access.decision else { return Err(PrivateOriginalError::Denied); };
        if decision.live_attachment.is_none() || access.mcp.is_none()
            || self.access_observation(task.grant.clone(), &access)?.state != PrivateServiceGrantState::GrantIssued {
            return Err(PrivateOriginalError::Denied);
        }
        let lifetime = self.host_lifetime.get().and_then(std::sync::Weak::upgrade)
            .ok_or(PrivateOriginalError::Unavailable)?;
        let operator = self.service_operator_setup(lifetime)
            .map_err(|_| PrivateOriginalError::Unavailable)?;
        let review = operator.retained_service_review(&reference.route,
            &record.event.original_authentication, &access.parent).await
            .map_err(|_| PrivateOriginalError::Denied)?;
        let owner = self.installation_readback.get().ok_or(PrivateOriginalError::Unavailable)?;
        attachment_preparation_diagnostic::<()>("installation_owner_readback", None);
        let server = owner.readback(&review).await;
        attachment_preparation_diagnostic("installation_owner_readback", Some(&server));
        let server = server?;
        // The verifier may wait on filesystem/process work. Reopen the exact
        // B and parent grant afterward; this is not the final native Apply check.
        attachment_preparation_diagnostic::<()>("installation_post_records", None);
        let current = self.store.get(&stored.key).await.map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        let current_record = self.decode_record(&current, reference)?;
        let current_access = self.store.get(&access_stored.key).await.map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        attachment_preparation_diagnostic("installation_post_records", Some(&Ok::<(), PrivateOriginalError>(())));
        if current_record.approved_task != record.approved_task
            || current_record.final_association.is_some() || current_record.service_admission.is_some() {
            attachment_preparation_diagnostic("installation_record_changed", Some(&Err::<(), _>(PrivateOriginalError::Denied)));
            return Err(PrivateOriginalError::Denied);
        }
        let current_access = self.decode_access(&current_access, &task.grant);
        attachment_preparation_diagnostic("installation_access_decode", Some(&current_access));
        if current_access? != access {
            attachment_preparation_diagnostic("installation_access_changed", Some(&Err::<(), _>(PrivateOriginalError::Denied)));
            return Err(PrivateOriginalError::Denied);
        }
        attachment_preparation_diagnostic::<()>("installation_currentness", None);
        let current = self.service_task_submission_current(&current_record).await;
        attachment_preparation_diagnostic("installation_currentness", Some(&current));
        if !current? {
            attachment_preparation_diagnostic("installation_not_current", Some(&Err::<(), _>(PrivateOriginalError::Denied)));
            return Err(PrivateOriginalError::Denied);
        }
        let observed = self.access_observation(task.grant.clone(), &access);
        attachment_preparation_diagnostic("installation_grant_observation", Some(&observed));
        if observed?.state != PrivateServiceGrantState::GrantIssued {
            attachment_preparation_diagnostic("installation_grant_not_issued", Some(&Err::<(), _>(PrivateOriginalError::Denied)));
            return Err(PrivateOriginalError::Denied);
        }
        let bytes = canonical_json(&server).map_err(|_| PrivateOriginalError::Conflict)?;
        if digest(&bytes) != decision.connection_revision.as_str() {
            attachment_preparation_diagnostic("installation_connection_changed", Some(&Err::<(), _>(PrivateOriginalError::Denied)));
            return Err(PrivateOriginalError::Denied);
        }
        attachment_preparation_diagnostic("installation_connection_digest", Some(&Ok::<(), PrivateOriginalError>(())));
        Ok(server)
    }
}
