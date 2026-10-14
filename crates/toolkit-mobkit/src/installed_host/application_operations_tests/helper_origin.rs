//! Actual installed policy, registered bundle witnesses and retained source
//! rows. Native dispatch, input admission and human presentation are not run.
use super::*;
use crate::original_ingress::helper_originals::{
    HelperAdmissionSelection, HelperNativeBinding, HelperSetupOrigin, retained_policy_fixture,
};
use meerkat_core::service::WorkGraphNamespaceGrant;
use meerkat_workgraph::{SqliteWorkGraphStore, WorkGraphService};

struct HelperFixture {
    installed: Fixture,
    association: InputAuthorityAssociation,
    origin: HelperSetupOrigin,
    session: SessionId,
}
impl HelperFixture {
    async fn new() -> Self {
        let installed = Fixture::new().await;
        let native = &installed.application.native;
        assert!(installed.association.candidate().original_work.authority != native.ingress_domain.authority);
        let controller_parent = native.routes[0].controller_parent.clone().unwrap();
        let operation_parent = native.routes[0].application_parent.clone().unwrap();
        let executor = native.routes[0].logical_executor.clone();
        let child = |parent: &[GrantLineageRef], label: &str| {
            let leaf = installed.source.grants().issue_child(
                &native.grant_administrator, parent.last().unwrap(), id(label), executor.clone(),
                ExecutionRestrictions { delegation_depth: DelegationDepth::remaining(0),
                    ..ExecutionRestrictions::unrestricted() },
            ).unwrap();
            let mut lineage = parent.to_vec(); lineage.push(leaf); lineage
        };
        // Independent real children preserve the existing fixture's memory
        // ceiling. The local operation projection below is not a report grant.
        let controller = child(&controller_parent, "origin-policy-controller");
        let basis = WorkAuthorityBasis::GrantLineage {
            lineage: child(&operation_parent, "origin-policy-memory"),
        };
        let member = native.members[0].clone();
        let selection = HelperAdmissionSelection {
            helper: super::super::acquisition::InstalledSetupSelection {
                report_capability: None, member: member.member.clone(),
                ingress_actor: super::super::tests::principal("helper-owner"),
                logical_executor: executor, represented_subject: None,
                controller_parent, operation_basis: basis.clone(),
            },
            member, grant_caller: native.grant_administrator.clone(),
        };
        let session = SessionId::new();
        assert_ne!(session, installed.session);
        let mut target = installed.association.candidate().target.clone();
        target.context = id(&session.to_string());
        target.logical_runtime = id(&meerkat_runtime::LogicalRuntimeId::for_session(&session).to_string());
        let binding = HelperNativeBinding {
            ingress_actor: selection.helper.ingress_actor.clone(),
            logical_executor: selection.helper.logical_executor.clone(), represented_subject: None,
            target, authority_basis: basis, controller_grant_lineage: controller,
            controller_model: selected(&installed.facts),
            controller_ceiling: installed.association.candidate().controller_ceiling.clone(),
            admitted_ceiling: installed.association.candidate().admitted_ceiling.clone(),
        };
        let service = WorkGraphService::with_namespace_grant(
            Arc::new(SqliteWorkGraphStore::open(installed._directory.path().join("origin-policy.sqlite3")).unwrap()),
            WorkGraphNamespaceGrant::new(native.realm.to_string(), "setup").unwrap(),
        ).unwrap();
        let source = retained_policy_fixture(
            &installed.source, installed.application.originals.canonical_store_for_policy_fixture(),
            StoreScope { realm: native.realm.to_string(), owner: installed.application.selected.deployment.to_string() },
            &service, "origin-policy", installed.retained.clone(), vec![installed.retained.clone()],
            selection, binding,
        ).await;
        let origin = source.policy_source().unwrap().origin;
        assert!(origin.original_authority == installed.association.candidate().original_work.authority);
        assert!(origin.source_owner == installed.association.candidate().ingress_namespace.ingress);
        let association = source.original.association().clone();
        installed.application.originals.retain_helper_policy_fixture(source);
        Self { installed, association, origin, session }
    }

    fn binding(&self, call: &SetupBundleCall) -> PreparedAuthorizationBinding {
        PreparedAuthorizationBinding::new(OperationAuthorizationFacts {
            operation_id: serde_json::from_str("\"00000000-0000-0000-0000-000000000005\"").unwrap(),
            execution_scope: scope(&self.session), run_id: None, context_revision: None,
            operation: AuthorizationOperation::Tool(call.facts.clone()),
        })
    }

    fn values(&self, call: &SetupBundleCall)
        -> Result<LocalPolicyAllowance, OperationAuthorizationError>
    {
        self.installed.application.authorize_operation(
            &self.association, &self.binding(call), LocalPolicyPurpose::Operation, 0,
        )
    }
}

fn calls() -> [SetupBundleCall; 3] {
    [
        SetupBundleCall::new(meerkat_toolkit::setup::SETUP_RESULTS_BUNDLE, meerkat_toolkit::setup::SETUP_REPORT),
        SetupBundleCall::new(meerkat_toolkit::setup::SETUP_ACCOUNTS_BUNDLE, meerkat_toolkit::setup::SETUP_ACCOUNT_REQUEST),
        SetupBundleCall::new(meerkat_toolkit::setup::SETUP_ACCOUNTS_BUNDLE, meerkat_toolkit::setup::SETUP_PUBLIC_SERVICE_REQUEST),
    ]
}

#[tokio::test]
async fn registered_helper_operations_project_the_retained_qualified_origin() {
    let fixture = HelperFixture::new().await;
    let native = &fixture.installed.application.native;
    let claims = fixture.association.candidate();
    let [report, account, public] = calls();
    let report_values = fixture.values(&report).unwrap().operation_values.remove(0);
    let account_values = fixture.values(&account).unwrap().operation_values.remove(0);
    let public_values = fixture.values(&public).unwrap().operation_values.remove(0);
    let expected = application_operations::setup_report_for_origin(
        &native.grant_administrator, &claims.logical_executor, &claims.target.audience, &fixture.origin,
    ).unwrap();
    assert_eq!(report_values.resource_domain, expected.resource_domain);
    assert_eq!(report_values.action, expected.action);
    assert_eq!(report_values.processor, expected.processor);
    assert_eq!(report_values.audience, expected.audience);
    assert_eq!(report_values.resource_domain.authority, native.grant_administrator);
    assert_ne!(report_values.resource_domain, account_values.resource_domain);
    assert_ne!(report_values.action, account_values.action);
    assert_ne!(public_values.action, account_values.action);
    assert_ne!(public_values.action, report_values.action);
    assert_ne!(public_values.resource_domain, account_values.resource_domain);
    assert_ne!(public_values.resource_domain, report_values.resource_domain);
    let public_expected = application_operations::setup_public_service_request_for_origin(
        &native.grant_administrator, &claims.logical_executor, &claims.target.audience, &fixture.origin,
    ).unwrap();
    assert_eq!(public_values.action, public_expected.action);
    assert_eq!(public_values.resource_domain, public_expected.resource_domain);
    assert_eq!(public_values.processor, public_expected.processor);
    assert_eq!(public_values.audience, public_expected.audience);
    assert_eq!(account_values.resource_domain, application_operations::setup_account_request_for_origin(
        &native.grant_administrator, &claims.logical_executor, &claims.target.audience, &fixture.origin,
    ).unwrap().resource_domain);
    // These rows have only the fixture's memory grant. The real native
    // restriction owner still excludes all three projected operations.
    let lineage = claims.authority_basis.lineage_for(None).unwrap();
    let grant = fixture.installed.source.grants().resolve_lineage(
        lineage, &claims.logical_executor, claims.represented_subject.as_ref(),
    ).unwrap();
    assert!(!in_bounds(grant.restrictions(), &report_values));
    assert!(!in_bounds(grant.restrictions(), &account_values));
    assert!(!in_bounds(grant.restrictions(), &public_values));
    assert_eq!(report.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(account.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(public.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn helper_projection_refuses_nonhelper_changed_target_and_closed_owner() {
    let fixture = HelperFixture::new().await;
    for call in calls() {
        denied(fixture.installed.application.authorize_operation(
            &fixture.installed.association, &fixture.binding(&call), LocalPolicyPurpose::Operation, 0,
        ));
        for field in 0..4 {
            let mut changed = fixture.association.candidate().clone();
            match field {
                0 => changed.target.context = id(&SessionId::new().to_string()),
                1 => changed.logical_executor = super::super::tests::principal("other-helper"),
                2 => changed.target.audience = AudienceRef::Principal {
                    principal: super::super::tests::principal("other-audience"),
                },
                3 => changed.ingress_namespace.realm = meerkat_core::RealmId::parse("other-realm").unwrap(),
                _ => unreachable!(),
            }
            let changed = InputAuthorityAssociation::new(changed).unwrap();
            assert!(fixture.installed.application.authorize_operation(
                &changed, &fixture.binding(&call), LocalPolicyPurpose::Operation, 0,
            ).is_err());
        }
        assert_eq!(call.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
    fixture.installed.lifetime.begin_close_activation(HostCloseReason::OperatorDisable).unwrap();
    for call in calls() {
        denied(fixture.values(&call));
        assert_eq!(call.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}

fn in_bounds(bounds: &ExecutionRestrictions, values: &meerkat_authorization::policy::LocalOperationValues) -> bool {
    bounds.check_bounds(meerkat_authorization_contracts::constraints::OperationRestrictionValues {
        action: &values.action, resource_domain: &values.resource_domain,
        processor: &values.processor, audience: &values.audience, now_ms: 0,
    }).is_ok()
}
