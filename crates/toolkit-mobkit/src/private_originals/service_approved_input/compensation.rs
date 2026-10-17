//! Joined approval failure reconciliation. The existing intent records and
//! native grant authority remain the only durable owners. Abrupt future drop
//! and process loss still require retained-intent recovery; Drop is not revoke.
use super::*;
use crate::installed_host::operator_setup::ServiceMcpParentCompensation;

impl InstalledServiceTask {
    pub(super) async fn compensate_unpublished_approval(&self,
        cleanup: ServiceMcpParentCompensation, grant: PrivateServiceGrantRef,
    ) -> Result<(), PrivateOriginalError> {
        if !cleanup.belongs_to(&self.source.owner) { return Err(PrivateOriginalError::Denied); }
        let source = self.source.clone();
        source.owner.reconcile_followup_source(&self.parent_association, || async {
            let stored = source.store.get(&source.key(&self.parent)?).await.map_err(store_error)?
                .ok_or(PrivateOriginalError::Unavailable)?;
            let parent_source = source.decode_record(&stored, &self.parent)?;
            if parent_source.final_association.as_ref() != Some(&self.parent_association) {
                return Err(PrivateOriginalError::Conflict);
            }
            let key = StoreKey { realm: source.scope.realm.clone(), owner: source.scope.owner.clone(),
                id: source_key_id(&parent_source.source.realm, &parent_source.source.ingress,
                    &parent_source.source.source_authority, &self.fresh)? };
            let published = source.store.get(&key).await.map_err(store_error)?;
            let parent = cleanup.issued().await.map_err(application::policy_error)?;
            let Some(parent) = parent else { return Ok(()); };
            if let Some(published) = published {
                let record = source.decode_stored(&published)?;
                if record.source != parent_source.source || record.event.original != self.fresh {
                    return Err(PrivateOriginalError::Conflict);
                }
                let link = record.approved_task.as_ref().ok_or(PrivateOriginalError::Conflict)?;
                if link.parent != self.parent || link.acquisition != self.acquisition
                    || link.original_task != self.task {
                    return Err(PrivateOriginalError::Conflict);
                }
                // Preserve a successful exact replay or a lost source-commit
                // acknowledgement. A different approval can name the same task
                // but its parent does not acquire this published child's owner.
                if link.grant == grant && source.service_compensation_child(&grant, &parent).await?.is_some() {
                    return Ok(());
                }
            }
            // Revoke the parent first. Native serializes this with issue_child:
            // once acknowledged, no late worker can issue another child under
            // it. Then read the retained child intent and actual native owner.
            let machine = source.machine()?;
            let parent_result = match machine.try_controller_grant_mutation() {
                Ok(mut custody) => source.owner.grants().revoke(cleanup.issuer(), &parent, &mut custody)
                    .map_err(|_| PrivateOriginalError::Unavailable),
                Err(_) => Err(PrivateOriginalError::Unavailable),
            };
            let child_result = match source.service_compensation_child(&grant, &parent).await {
                Ok(Some((issuer, child))) => match machine.try_controller_grant_mutation() {
                    Ok(mut custody) => source.owner.grants().revoke(&issuer, &child, &mut custody)
                        .map_err(|_| PrivateOriginalError::Unavailable),
                    Err(_) => Err(PrivateOriginalError::Unavailable),
                },
                Ok(None) => Ok(()),
                Err(error) => Err(error),
            };
            parent_result.and(child_result)
        }).await.map_err(|_| PrivateOriginalError::Unavailable)?
    }
}
