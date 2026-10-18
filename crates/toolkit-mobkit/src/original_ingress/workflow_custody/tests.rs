//! Native grant/source-owner controls only. These do not launch a lead, enter
//! a native effect, deliver context, or establish installed SDK behavior.
use super::*;
use crate::original_ingress::tests::{claims, initialized, machine, principal, source};
use meerkat_core::OperationExecutionScope;
use meerkat_core::authorization::{
    AuthorizationOperation, OperationAuthorizationFacts, ToolAuthorizationFacts,
    ToolAuthorizationTarget,
};
use std::os::unix::fs::PermissionsExt;

fn id(value: &str) -> EvidenceId {
    EvidenceId::new(value).unwrap()
}
fn target() -> GrantTarget {
    GrantTarget::RegisteredToolBundleOperation {
        bundle: "workflow-owner-fixture".into(),
        operation: "prepare".into(),
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    owner: Arc<ToolkitOriginalOwner>,
    g: Arc<RetainedToolkitOriginal>,
    a: Arc<RetainedToolkitOriginal>,
    b: Arc<RetainedToolkitOriginal>,
    a_child: Vec<GrantLineageRef>,
    b_child: Vec<GrantLineageRef>,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let owner = initialized(&directory.path().join("grants"));
        let root = owner
            .grants
            .issue_root(
                &principal("admin"),
                id("base"),
                principal("admin"),
                None,
                ExecutionRestrictions::unrestricted(),
            )
            .unwrap();
        let make = |label: &str, executor: &str| {
            let mut candidate = claims(label, &root).candidate().clone();
            candidate.logical_executor = principal(executor);
            candidate.target.logical_owner = principal(executor);
            candidate.target.audience =
                meerkat_authorization_contracts::constraints::AudienceRef::Principal {
                    principal: principal(&format!("{label}-audience")),
                };
            let association = InputAuthorityAssociation::new(candidate).unwrap();
            let original = owner
                .enroll_new_authenticated(
                    association.clone(),
                    source(&association),
                    &principal("user"),
                    &principal("frontend"),
                    &principal("admin"),
                    id(&format!("{label}-original")),
                    ExecutionRestrictions::unrestricted(),
                    |_| Ok(None),
                )
                .unwrap();
            // Explicit native source-owner acknowledgment, not runtime input
            // admission. The existing owner/grant mechanisms are real here.
            owner.record_candidate(&original).unwrap().admit().unwrap();
            original
        };
        let g = make("g", "planning");
        let a = make("a", "waiter-a");
        let b = make("b", "waiter-b");
        let delegate = |original: &Arc<RetainedToolkitOriginal>, label: &str| {
            let parent = original
                .association
                .candidate()
                .authority_basis
                .lineage_for(Some(&target()))
                .unwrap();
            let child = owner
                .grants
                .issue_child(
                    &original.association.candidate().logical_executor,
                    parent.last().unwrap(),
                    id(label),
                    principal("planning"),
                    ExecutionRestrictions::unrestricted(),
                )
                .unwrap();
            let mut lineage = parent.to_vec();
            lineage.push(child);
            lineage
        };
        let a_child = delegate(&a, "a-to-g");
        let b_child = delegate(&b, "b-to-g");
        Self {
            _directory: directory,
            owner,
            g,
            a,
            b,
            a_child,
            b_child,
        }
    }
    fn relationship(
        &self,
        original: &Arc<RetainedToolkitOriginal>,
        child: Vec<GrantLineageRef>,
    ) -> Result<Arc<WorkflowWaiterCustody>, OriginalWriterError> {
        let _writer = self.owner.mutation.try_lock().unwrap();
        self.owner.workflow_waiter_custody(
            self.g.clone(),
            original.clone(),
            Id::new(original.association.candidate().original_work.work.as_str()).unwrap(),
            target(),
            child,
            u64::MAX,
        )
    }
}
struct Dispatcher;
#[async_trait::async_trait]
impl meerkat_core::AgentToolDispatcher for Dispatcher {
    fn tools(&self) -> Arc<[Arc<meerkat_core::ToolDef>]> {
        vec![Arc::new(meerkat_core::ToolDef {
            name: "prepare".into(),
            description: "inert workflow owner fixture".into(),
            input_schema: serde_json::json!({"type":"object"}),
            provenance: None,
            audience: meerkat_core::ToolAudience::Model,
        })]
        .into()
    }
    async fn dispatch(
        &self,
        call: ToolCallView<'_>,
    ) -> Result<meerkat_core::ops::ToolDispatchOutcome, meerkat_core::ToolError> {
        Err(meerkat_core::ToolError::unavailable(
            call.name,
            meerkat_core::ToolUnavailableReason::ExecutionOwnerChanged,
        ))
    }
}
struct Call {
    facts: ToolAuthorizationFacts,
}
impl Call {
    fn new(id: &str, arguments: &str) -> Self {
        let args: Arc<serde_json::value::RawValue> =
            serde_json::value::RawValue::from_string(arguments.into())
                .unwrap()
                .into();
        let root: Arc<dyn meerkat_core::AgentToolDispatcher> =
            Arc::new(meerkat_core::RegisteredToolBundleDispatcher::new(
                "workflow-owner-fixture",
                Arc::new(Dispatcher),
            ));
        let plan = meerkat_core::resolve_tool_execution_plan_fenced(
            &root,
            ToolCallView {
                id,
                name: "prepare",
                args: &args,
            },
            &meerkat_core::ToolDispatchContext::default(),
            &meerkat_core::ToolExecutionResolutionContext::new(
                meerkat_core::ToolDeadlineChain::new(vec![
                    meerkat_core::ToolDeadlineContributor::finite(
                        meerkat_core::ToolDeadlineOwner::CoreToolDispatch,
                        std::time::Duration::from_secs(60),
                    ),
                ])
                .unwrap(),
            ),
        )
        .unwrap();
        Self {
            facts: ToolAuthorizationFacts {
                call_id: Arc::from(id),
                name: "prepare".into(),
                arguments: args,
                target: ToolAuthorizationTarget::Dispatcher(Arc::new(plan)),
            },
        }
    }
    fn binding(&self) -> PreparedAuthorizationBinding {
        let uuid = |value: &str| format!("\"00000000-0000-0000-0000-{value}\"");
        PreparedAuthorizationBinding::new(OperationAuthorizationFacts {
            operation_id: serde_json::from_str(&uuid("000000000005")).unwrap(),
            execution_scope: OperationExecutionScope::RuntimeInput {
                owner_session_id: meerkat_core::SessionId::new(),
                runtime_epoch_id: serde_json::from_str(&uuid("000000000002")).unwrap(),
                submitted_input_id: serde_json::from_str(&uuid("000000000003")).unwrap(),
                canonical_input_id: serde_json::from_str(&uuid("000000000003")).unwrap(),
            },
            run_id: None,
            context_revision: None,
            operation: AuthorizationOperation::Tool(self.facts.clone()),
        })
    }
}

#[test]
fn original_grant_wrong_executor_and_foreign_source_cannot_become_a_to_g_delegation() {
    let f = Fixture::new();
    let original =
        f.a.association
            .candidate()
            .authority_basis
            .lineage_for(Some(&target()))
            .unwrap()
            .to_vec();
    assert!(f.relationship(&f.a, original).is_err());
    assert!(f.relationship(&f.a, f.b_child.clone()).is_err());
    let foreign = Fixture::new();
    assert!(f.relationship(&foreign.a, foreign.a_child.clone()).is_err());
    let parent =
        f.a.association
            .candidate()
            .authority_basis
            .lineage_for(Some(&target()))
            .unwrap();
    let other = f
        .owner
        .grants
        .issue_child(
            &principal("waiter-a"),
            parent.last().unwrap(),
            id("a-other"),
            principal("other"),
            ExecutionRestrictions::unrestricted(),
        )
        .unwrap();
    let mut wrong = parent.to_vec();
    wrong.push(other);
    assert!(f.relationship(&f.a, wrong).is_err());
    assert_ne!(
        f.g.association.candidate().target.audience,
        f.a.association.candidate().target.audience
    );
    assert!(f.relationship(&f.a, f.a_child.clone()).is_ok());
    assert!(
        f.owner.workflow_controller(&f.g).is_err(),
        "fixture has no actual native controller"
    );
}

#[test]
fn staged_call_retains_operation_binding_and_refuses_equal_fact_reconstruction() {
    let f = Fixture::new();
    let relationship = f.relationship(&f.a, f.a_child.clone()).unwrap();
    let call = Call::new("a-call", "{\"waiter\":\"a\"}");
    let (_, before) = f.owner.publication.observe(|| ()).unwrap();
    let staged = relationship.stage_call(call.facts.call()).unwrap();
    assert!(before.check_current().is_err());
    let binding = call.binding();
    let prepared = relationship
        .prepared_call(f.g.association(), &binding)
        .unwrap()
        .unwrap();
    assert!(Arc::ptr_eq(&prepared, &staged));
    assert!(
        relationship
            .prepared_call(f.g.association(), &binding.clone())
            .unwrap()
            .is_some()
    );
    let reconstructed = PreparedAuthorizationBinding::new(binding.facts().clone());
    assert!(
        relationship
            .prepared_call(f.g.association(), &reconstructed)
            .is_err()
    );
    let changed = Call::new("a-call", "{\"waiter\":\"b\"}");
    assert!(relationship.stage_call(changed.facts.call()).is_err());
    assert!(
        relationship
            .prepared_call(f.a.association(), &binding)
            .is_err()
    );
    staged.settle().unwrap();
    assert!(staged.current().is_err());
}

#[test]
fn revoking_a_after_preparation_invalidates_its_publication_while_b_remains_usable() {
    let f = Fixture::new();
    let a = f.relationship(&f.a, f.a_child.clone()).unwrap();
    let b = f.relationship(&f.b, f.b_child.clone()).unwrap();
    let ca = Call::new("a-call", "{}");
    let cb = Call::new("b-call", "{}");
    let aa = a.stage_call(ca.facts.call()).unwrap();
    let bb = b.stage_call(cb.facts.call()).unwrap();
    let ba = ca.binding();
    let binding_b = cb.binding();
    let (_, stamp) = f
        .owner
        .publication
        .observe(|| {
            a.prepared_call(f.g.association(), &ba).unwrap().unwrap();
            b.prepared_call(f.g.association(), &binding_b)
                .unwrap()
                .unwrap();
        })
        .unwrap();
    let native = machine(&f.owner);
    let mut custody = native.try_controller_grant_mutation().unwrap();
    f.owner
        .grants
        .revoke(
            &principal("waiter-a"),
            f.a_child.last().unwrap(),
            &mut custody,
        )
        .unwrap();
    drop(custody);
    assert!(stamp.check_current().is_err());
    assert!(aa.current().is_err());
    assert!(a.prepared_call(f.g.association(), &ba).is_err());
    assert!(bb.current().is_ok());
    assert!(
        b.prepared_call(f.g.association(), &binding_b)
            .unwrap()
            .is_some()
    );
    // This is the actual local source gate, not Core's final native entry.
    assert!(aa.enter_source_gate().is_err());
    bb.enter_source_gate().unwrap();
    aa.settle().unwrap();
    bb.settle().unwrap();
}

#[test]
fn retiring_a_after_preparation_closes_only_a_and_does_not_reopen_on_replay() {
    let f = Fixture::new();
    let a = f.relationship(&f.a, f.a_child.clone()).unwrap();
    let b = f.relationship(&f.b, f.b_child.clone()).unwrap();
    let ca = Call::new("a-call", "{}");
    let cb = Call::new("b-call", "{}");
    let aa = a.stage_call(ca.facts.call()).unwrap();
    let bb = b.stage_call(cb.facts.call()).unwrap();
    a.prepared_call(f.g.association(), &ca.binding()).unwrap();
    b.prepared_call(f.g.association(), &cb.binding()).unwrap();
    let (_, stamp) = f.owner.publication.observe(|| ()).unwrap();
    // The grant observation has succeeded, but retirement wins the source
    // writer before the staging mutation. No new pending entry may escape it.
    a.current_grant().unwrap();
    a.retire().unwrap();
    let late = Call::new("late-a-call", "{}");
    let count = f.owner.shared_entries.lock().unwrap().len();
    assert!(a.stage_current_call(late.facts.call()).is_err());
    assert_eq!(f.owner.shared_entries.lock().unwrap().len(), count);
    assert!(stamp.check_current().is_err());
    assert!(aa.enter_source_gate().is_err());
    assert!(a.stage_call(ca.facts.call()).is_err());
    assert!(bb.current().is_ok());
    bb.enter_source_gate().unwrap();
    aa.settle().unwrap();
    bb.settle().unwrap();
}

#[test]
fn delegation_requires_its_own_connector_record_and_actual_g_audience() {
    use meerkat_authorization::mcp_installation::mcp_connector_action;
    use meerkat_authorization::policy::LocalOperationValues;
    use meerkat_authorization_contracts::constraints::{
        AudienceRef, ExactRestriction, OperationRestrictionValues, ProcessorRef,
    };
    use meerkat_core::{McpConnectorApproval, OperationReviewTier};
    let f = Fixture::new();
    let domain = ResourceDomain {
        authority: principal("operator"),
        namespace: "realm/current/mcp".into(),
    };
    let connector = mcp_connector_action("setup", &McpConnectorApproval::NoConnector);
    let g_audience = f.g.association.candidate().target.audience.clone();
    let recorded = |approval: &McpConnectorApproval, audience: AudienceRef| ExecutionRestrictions {
        actions: ExactRestriction::exact([mcp_connector_action("setup", approval)]),
        resource_domains: ExactRestriction::exact([domain.clone()]),
        audiences: ExactRestriction::exact([audience]),
        ..ExecutionRestrictions::unrestricted()
    };
    let resolve = |label: &str, restrictions: ExecutionRestrictions| {
        let parent = f
            .owner
            .grants
            .issue_root(
                &principal("admin"),
                id(&format!("{label}-root")),
                principal("waiter-a"),
                None,
                restrictions,
            )
            .unwrap();
        let child = f
            .owner
            .grants
            .issue_child(
                &principal("waiter-a"),
                &parent,
                id(&format!("{label}-to-g")),
                principal("planning"),
                ExecutionRestrictions::unrestricted(),
            )
            .unwrap();
        f.owner
            .grants
            .resolve_lineage(&[parent, child], &principal("planning"), None)
            .unwrap()
    };
    // This independent grant explicitly records the actual G connector. It
    // cannot lend that record to any of the distinct A delegations below.
    let g = resolve(
        "g-recorded",
        recorded(&McpConnectorApproval::NoConnector, g_audience.clone()),
    );
    let values = LocalOperationValues {
        action: connector,
        resource_domain: domain.clone(),
        processor: ProcessorRef::Principal {
            principal: principal("planning"),
        },
        audience: g_audience.clone(),
    };
    let allowance = || LocalPolicyAllowance {
        operation_values: vec![values.clone()],
        restrictions: g.restrictions().clone(),
        expires_at_ms: u64::MAX,
        review_tier: OperationReviewTier::R1,
    };
    let matches_actual = |allowance: &LocalPolicyAllowance| {
        allowance
            .restrictions
            .check_bounds(OperationRestrictionValues {
                action: &values.action,
                resource_domain: &values.resource_domain,
                processor: &values.processor,
                audience: &values.audience,
                now_ms: 10,
            })
    };
    let unrecorded = resolve("a-unrecorded", ExecutionRestrictions::unrestricted());
    assert!(matches!(
        narrow_delegation_allowance(&unrecorded, u64::MAX, &mut allowance(), 10),
        Err(OperationAuthorizationError::Unavailable)
    ));
    let other = resolve(
        "a-other",
        recorded(
            &McpConnectorApproval::Connector("sha256:other".into()),
            g_audience.clone(),
        ),
    );
    assert!(matches!(
        narrow_delegation_allowance(&other, u64::MAX, &mut allowance(), 10),
        Err(OperationAuthorizationError::Refused(_))
    ));
    let approved = resolve(
        "a-approved",
        recorded(&McpConnectorApproval::NoConnector, g_audience.clone()),
    );
    let mut checked = allowance();
    narrow_delegation_allowance(&approved, u64::MAX, &mut checked, 10).unwrap();
    matches_actual(&checked).unwrap();
    // Distinct source audiences are allowed, but the actual G recipient must
    // remain in the independently delegated A grant's bound.
    let excludes_g = resolve(
        "a-excludes-g",
        recorded(
            &McpConnectorApproval::NoConnector,
            f.a.association.candidate().target.audience.clone(),
        ),
    );
    let mut denied = allowance();
    narrow_delegation_allowance(&excludes_g, u64::MAX, &mut denied, 10).unwrap();
    assert!(matches_actual(&denied).is_err());
}


#[tokio::test]
async fn terminal_membership_retirement_preserves_a_original_and_b_staged_call() {
    let f = Fixture::new();
    let a = f.relationship(&f.a, f.a_child.clone()).unwrap();
    let b = f.relationship(&f.b, f.b_child.clone()).unwrap();
    let ca = Call::new("terminal-a", "{}");
    let entered_a = Call::new("entered-a", "{}");
    let cb = Call::new("live-b", "{}");
    let aa = a.stage_call(ca.facts.call()).unwrap();
    let entered = a.stage_call(entered_a.facts.call()).unwrap();
    let bb = b.stage_call(cb.facts.call()).unwrap();
    let ba = ca.binding();
    let be = entered_a.binding();
    let binding_b = cb.binding();
    let (_, stamp) = f.owner.publication.observe(|| {
        a.prepared_call(f.g.association(), &ba).unwrap().unwrap();
        a.prepared_call(f.g.association(), &be).unwrap().unwrap();
        b.prepared_call(f.g.association(), &binding_b).unwrap().unwrap();
    }).unwrap();
    entered.enter_source_gate().unwrap();
    // This is the actual local staged-call owner, not native effect-entry proof.
    // Retirement uses the same writer as relationship insertion. An unrelated
    // owner/Original in the selected vector refuses before any retirement.
    assert!(f.owner.retire_workflow_membership(f.a.association(), || Ok(vec![b.clone()]))
        .await.is_err());
    assert!(aa.current().is_ok() && bb.current().is_ok());
    {
        let _writer = f.owner.mutation.try_lock().unwrap();
        assert!(f.owner.retire_workflow_membership(f.a.association(), || Ok(vec![a.clone()]))
            .await.is_err());
    }
    f.owner.retire_workflow_membership(f.a.association(), || Ok(vec![a.clone()])).await.unwrap();
    assert!(stamp.check_current().is_err());
    assert!(aa.current().is_err());
    assert!(aa.enter_source_gate().is_err());
    assert!(a.stage_call(Call::new("late-a", "{}").facts.call()).is_err());
    assert!(bb.current().is_ok());
    bb.enter_source_gate().unwrap();
    f.owner.workflow_source_current(&f.a).unwrap();
    f.owner.workflow_source_current(&f.b).unwrap();
    assert!(!entered.entry.settled(), "retirement does not invent entered completion");
    let (_, replay_stamp) = f.owner.publication.observe(|| ()).unwrap();
    f.owner.retire_workflow_membership(f.a.association(), || Ok(vec![a.clone()])).await.unwrap();
    replay_stamp.check_current().unwrap();
    entered.settle().unwrap();
    aa.settle().unwrap();
    bb.settle().unwrap();
}
