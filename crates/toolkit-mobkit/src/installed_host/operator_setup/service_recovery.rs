//! Typed historical service-approval correlation. Reading these records never
//! recreates a review, issues access, or restores an original's admission.
use super::*;
use crate::private_originals::{PrivateServiceMcpAccessDecision, PrivateServiceMcpLiveAttachment};
use meerkat_authorization_contracts::work_association::OriginalWorkRef;
use meerkat_core::{PrincipalRef, RealmId};

#[derive(Clone, Deserialize)]
pub(crate) struct ServiceApprovalContext {
    pub prior_original: OriginalWorkRef,
    pub fresh_original: EvidenceId,
    pub business_task: StoreKey,
    pub live_attachment: PrivateServiceMcpLiveAttachment,
    pub operator_and_requester: PrincipalRef,
    pub ingress_actor: PrincipalRef,
    pub represented_subject: Option<PrincipalRef>,
    pub audience: meerkat_authorization_contracts::constraints::AudienceRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentBody {
    operator: PrincipalRef,
    application: PrincipalRef,
    realm: RealmId,
    route: Id,
    purpose: OperatorParentPurpose,
    represented_subject: Option<PrincipalRef>,
    restrictions: ExecutionRestrictions,
    service_access: PrivateServiceMcpAccessDecision,
    connector_selection: serde_json::Value,
    access_request: serde_json::Value,
}

pub(crate) struct RetainedServiceApproval {
    pub stored: StoredRecord,
    pub context: ServiceApprovalContext,
    pub decision: PrivateServiceMcpAccessDecision,
    pub selection: serde_json::Value,
    pub policy: Option<crate::private_originals::ServiceToolPolicyProposal>,
    pub cleanup: ServiceMcpParentCompensation,
    pub requested: ExecutionRestrictions,
    pub application: PrincipalRef,
    pub represented_subject: Option<PrincipalRef>,
}

pub(crate) fn is_parent_record(stored: &StoredRecord) -> bool {
    stored.data.schema == SCHEMA
}

impl OperatorSetup {
    pub(crate) fn recovery_operator(&self) -> &PrincipalRef {
        &self.operator
    }

    pub(crate) fn retained_service_approval(
        &self,
        stored: &StoredRecord,
    ) -> Result<Option<RetainedServiceApproval>, HostLifetimeError> {
        if !is_parent_record(stored) {
            return Ok(None);
        }
        let record = decode(stored, &stored.key)?;
        if self.parent_decision_key(&record)? != stored.key {
            return Err(HostLifetimeError::InvalidSelection);
        }
        if record.operator != self.operator
            || record.application != self.native.grant_administrator
            || record.purpose != OperatorParentPurpose::Operations
            || record.setup_request.is_some()
        {
            return Ok(None);
        }
        let Some(body) = record.approval.proposed_action.body.as_ref() else {
            return Ok(None);
        };
        if body
            .get("access_request")
            .and_then(|body| body.get("service_instruction"))
            .is_none()
        {
            return Ok(None);
        }
        let body: ParentBody = serde_json::from_value(body.clone())
            .map_err(|_| HostLifetimeError::InvalidSelection)?;
        if body.operator != record.operator
            || body.application != record.application
            || body.realm != self.native.realm
            || body.route != record.route
            || body.purpose != record.purpose
            || body.represented_subject != record.represented_subject
            || body.restrictions != record.requested
        {
            return Err(HostLifetimeError::InvalidSelection);
        }
        if !matches!((&record.approval.decision, record.approval.status),
            (Some(decision), ApprovalStatus::Approved) if decision.decision == ApprovalDecision::Approve)
        {
            return Ok(None);
        }
        let context: ServiceApprovalContext =
            serde_json::from_value(body.access_request["service_instruction"].clone())
                .map_err(|_| HostLifetimeError::InvalidSelection)?;
        let decision = body.service_access;
        if decision.choice != crate::private_originals::PrivateAccessChoice::Approve
            || decision.route != record.route
            || decision.decision.as_str() != context.fresh_original.as_str()
            || decision.evidence.resource_id != context.fresh_original
            || decision.evidence.sha256
                != format!(
                    "{:x}",
                    Sha256::digest(
                        canonical_json(&body.access_request)
                            .map_err(|_| HostLifetimeError::InvalidSelection)?
                    )
                )
            || decision.live_attachment.as_ref() != Some(&context.live_attachment)
        {
            return Err(HostLifetimeError::InvalidSelection);
        }
        let policy = body
            .access_request
            .get("member_tool_policy")
            .map(|policy| {
                serde_json::from_value(
                    policy
                        .get("proposal")
                        .ok_or(HostLifetimeError::InvalidSelection)?
                        .clone(),
                )
                .map_err(|_| HostLifetimeError::InvalidSelection)
            })
            .transpose()?;
        Ok(Some(RetainedServiceApproval {
            stored: stored.clone(),
            context,
            decision,
            selection: body.connector_selection,
            policy,
            requested: record.requested.clone(),
            application: record.application.clone(),
            represented_subject: record.represented_subject.clone(),
            cleanup: self.retained_service_compensation(record, stored.key.clone()),
        }))
    }
}
