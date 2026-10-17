//! Installed owner controls, including a real native input fixture without setup-worker launch.
use super::*;
use crate::installed_host::{InstalledToolkitHost, NativeOwnerStartup};
use meerkat_core::{ToolCallView, ToolDispatchContext, ToolError};
use meerkat_toolkit::host_lifetime::{NativeHostLifetime, control::{HostCloseReason, PrivateHostLifetimeControl}};
use serde_json::value::RawValue;

async fn installed() -> (tempfile::TempDir, Arc<NativeHostLifetime>, InstalledToolkitHost) {
    let (directory, mut selection) = crate::installed_host::tests::fixture();
    crate::installed_host::tests::provision_fixture(&mut selection);
    let (owner, installed) = InstalledToolkitHost::open(selection, NativeOwnerStartup::Restore).await.unwrap();
    let owner = Arc::new(owner);
    installed.originals.bind_host_lifetime(&owner).unwrap();
    (directory, owner, installed)
}

fn acquisition(installed: &InstalledToolkitHost, directory: &std::path::Path,
    tools: InstalledAcquisitionTools) -> Arc<InstalledAcquisition> {
    use meerkat_core::{service::WorkGraphNamespaceGrant, storage_durability::{DurabilityDeclaration, DurabilityResolution}};
    use meerkat_toolkit::{authority::Ceiling, setup::WorkAdmissionStepOptions};
    use meerkat_workgraph::{SqliteWorkGraphStore, WorkGraphService};
    let id = |value: &str| Id::new(value).unwrap();
    let native = &installed.native;
    let service = WorkGraphService::with_namespace_grant(
        Arc::new(SqliteWorkGraphStore::open(&directory.join("workgraph.sqlite")).unwrap()),
        WorkGraphNamespaceGrant::new(native.realm.as_str(), "setup").unwrap(),
    ).unwrap();
    let backend = SetupWorkBackend::new(service, "fixture".into(), id("generation"), &[
        DurabilityDeclaration::durable("workgraph", DurabilityResolution::Persistent),
    ]).unwrap();
    let parent = native.routes[0].application_parent.clone().unwrap();
    let helper = InstalledSetupSelection {
        catalog_capability: None,
        report_capability: None,
        member: native.members[0].member.clone(),
        ingress_actor: native.grant_administrator.clone(),
        logical_executor: native.members[0].logical_owner.clone(),
        represented_subject: None, controller_parent: parent.clone(),
        operation_basis: WorkAuthorityBasis::GrantLineage { lineage: parent },
    };
    let continuation = installed.native_continuation([id("private")].into()).unwrap();
    Arc::new(InstalledAcquisition::from_defaults_with_tools(
        installed.store.clone(), installed.source_scope.clone(), installed.originals.clone(), native,
        InstalledSetupDefaults {
            helper, proposal_ceiling: Ceiling { actions: Default::default(), services: Default::default(),
                frontends: Default::default(), output_audiences: [id("private")].into() },
            continuation, work_backend: backend, references: None,
            limits: InstalledSetupLimits::default(),
            work_step: WorkAdmissionStepOptions { worker: id("worker"), lease_ms: 100,
                owner_timeout_ms: 25, settlement_budget_ms: 25 },
        }, tools,
    ).unwrap())
}

#[tokio::test]
async fn unbound_dispatchers_refuse_before_context_admission_and_have_no_dependencies() {
    let tools = InstalledAcquisitionTools::new(Duration::from_secs(10)).unwrap();
    let cloned = tools.clone();
    assert!(Arc::ptr_eq(&tools.acquisition_tool(), &cloned.acquisition_tool()));
    assert!(Arc::ptr_eq(&tools.result_tool(), &cloned.result_tool()));
    assert_eq!(tools.acquisition_tool().tools()[0].identity(), crate::definition().identity());
    assert_eq!(tools.result_tool().tools()[0].identity(), results::setup_report_definition().identity());
    assert!(tools.0.binding.owner.get().is_none());
    assert!(matches!(&tools.0.acquisition.admission, crate::FindAndInstallAdmission::Installed(_)));
    let args = RawValue::from_string("{}".into()).unwrap();
    let context = ToolDispatchContext::default();
    // Actual production dispatch must observe the missing owner before it
    // interprets context, arguments or any canonical acquisition row.
    let result = tools.0.acquisition.dispatch_with_context(
        ToolCallView { id: "unbound", name: crate::FIND_AND_INSTALL, args: &args }, &context,
    ).await;
    assert!(matches!(result, Err(ToolError::Unavailable { .. })));
    let result = tools.result_tool().dispatch_with_context(ToolCallView {
        id: "unbound-result", name: meerkat_toolkit::setup::SETUP_REPORT, args: &args,
    }, &context).await;
    assert!(matches!(result, Err(ToolError::Unavailable { .. })));
    // Neither leaf even retains a source/store until this actual binding exists.
    assert!(tools.0.acquisition.admission_owner().is_err());
}

#[tokio::test]
async fn same_leaves_bind_once_to_the_creating_owner_and_expire_with_it() {
    let (directory, _lifetime, installed) = installed().await;
    let tools = InstalledAcquisitionTools::new(Duration::from_secs(10)).unwrap();
    let owner = acquisition(&installed, directory.path(), tools.clone());
    let foreign = InstalledAcquisitionTools::new(Duration::from_secs(10)).unwrap();
    assert!(foreign.bind(&owner).is_err());
    assert!(tools.0.binding.owner.get().is_none());
    owner.bind_tool_driver().unwrap();
    assert!(Arc::ptr_eq(&tools.acquisition_tool(), &owner.tool()));
    assert!(Arc::ptr_eq(&tools.result_tool(), &owner.result_tool()));
    let held = tools.0.acquisition.admission_owner().unwrap();
    assert!(Arc::ptr_eq(held.acquisition.as_ref().unwrap(), &owner));
    assert!(Arc::ptr_eq(held.dependencies.conditional_store.as_ref().unwrap(), &installed.store));
    assert!(tools.bind(&owner).is_err());
    assert!(tools.require_unbound(Duration::from_secs(10)).is_err());
    drop(held);
    drop(owner);
    assert!(tools.0.binding.owner.get().is_some());
    assert!(tools.0.acquisition.admission_owner().is_err());
}

#[tokio::test]
async fn closed_final_owner_refuses_and_timeout_cannot_change_after_enrollment() {
    let (directory, lifetime, installed) = installed().await;
    let tools = InstalledAcquisitionTools::new(Duration::from_secs(10)).unwrap();
    assert!(tools.require_unbound(Duration::from_secs(11)).is_err());
    let owner = acquisition(&installed, directory.path(), tools.clone());
    owner.bind_tool_driver().unwrap();
    assert!(tools.0.acquisition.admission_owner().is_ok());
    lifetime.begin_close_activation(HostCloseReason::Shutdown).unwrap();
    assert!(tools.0.acquisition.admission_owner().is_err());
    assert!(tools.0.binding.owner.get().and_then(Weak::upgrade).is_some(),
        "the refusal is actual close, not a dropped owner");
}

#[tokio::test]
async fn configured_owner_without_native_identity_refuses_both_production_leaves() {
    let (directory, _lifetime, installed) = installed().await;
    let tools = InstalledAcquisitionTools::new(Duration::from_secs(10)).unwrap();
    let owner = acquisition(&installed, directory.path(), tools.clone());
    owner.bind_tool_driver().unwrap();
    assert!(tools.0.binding.owner().is_some(), "the installed source is alive");
    assert!(tools.0.binding.execution_owner().is_none(), "configuration is not native binding");
    let args = RawValue::from_string("{}".into()).unwrap();
    for (tool, name) in [(tools.acquisition_tool(), crate::FIND_AND_INSTALL),
        (tools.result_tool(), meerkat_toolkit::setup::SETUP_REPORT)] {
        assert!(matches!(tool.dispatch_with_context(ToolCallView {
            id: "unbound-native", name, args: &args,
        }, &ToolDispatchContext::default()).await, Err(ToolError::Unavailable { .. })));
    }
    let scope = toolkit_store::StoreScope { realm: owner.host.tenant.to_string(),
        owner: format!("toolkit/acquisition/{}", owner.host.deployment) };
    assert!(owner.store.list_records(&scope, None, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn production_leaves_reach_actual_bound_owner_but_not_missing_native_continuation() {
    use crate::private_originals::ContinuationFixture;
    use futures::FutureExt;
    use std::panic::AssertUnwindSafe;
    use meerkat_core::{service::WorkGraphNamespaceGrant,
        storage_durability::{DurabilityDeclaration, DurabilityResolution}};
    use meerkat_workgraph::{SqliteWorkGraphStore, WorkGraphService};
    use meerkat_toolkit::{authority::Ceiling, setup::WorkAdmissionStepOptions};

    let fixture = ContinuationFixture::for_continuation().await;
    let result = AssertUnwindSafe(Box::pin(async {
        let admitted = fixture.submit().await;
        fixture.finish(&admitted).await.unwrap();
        let context = fixture.probe.as_ref().unwrap().captured();
        let before_inputs = fixture.inputs().await.unwrap();
        let before_requests = fixture.model_requests();
        let native = fixture.lifetime().selected_policy().native_host.as_ref().unwrap();
        let id = |value: &str| Id::new(value).unwrap();
        let continuation = InstalledNativeContinuation::new(fixture.store.clone(), fixture.scope.clone(),
            fixture.source.clone(), id("availability-control"), [id("person")].into()).unwrap();
        let service = WorkGraphService::with_namespace_grant(
            Arc::new(SqliteWorkGraphStore::open(&fixture.source_path.with_file_name("availability-workgraph.sqlite")).unwrap()),
            WorkGraphNamespaceGrant::new(native.realm.as_str(), "setup").unwrap(),
        ).unwrap();
        let backend = SetupWorkBackend::new(service, "fixture".into(), id("generation"), &[
            DurabilityDeclaration::durable("workgraph", DurabilityResolution::Persistent),
        ]).unwrap();
        let tools = InstalledAcquisitionTools::new(Duration::from_secs(10)).unwrap();
        let owner = Arc::new(InstalledAcquisition::from_defaults_with_tools(
            fixture.store.clone(), fixture.scope.clone(), fixture.source.clone(), native,
            InstalledSetupDefaults {
                helper: InstalledSetupSelection {
                    catalog_capability: None,
                    report_capability: None,
                    member: native.members[0].member.clone(), ingress_actor: native.grant_administrator.clone(),
                    logical_executor: native.members[0].logical_owner.clone(), represented_subject: None,
                    controller_parent: native.routes[0].controller_parent.clone().unwrap(),
                    operation_basis: WorkAuthorityBasis::TargetedGrantLineages { base: None, targets: vec![] },
                },
                proposal_ceiling: Ceiling { actions: Default::default(), services: Default::default(),
                    frontends: Default::default(), output_audiences: [id("person")].into() },
                continuation, work_backend: backend, references: None,
                limits: InstalledSetupLimits::default(),
                work_step: WorkAdmissionStepOptions { worker: id("worker"), lease_ms: 100,
                    owner_timeout_ms: 25, settlement_budget_ms: 25 },
            }, tools.clone(),
        ).unwrap());
        owner.bind_tool_driver().unwrap();
        assert!(Arc::ptr_eq(&tools.0.binding.execution_owner().unwrap(), &owner));
        // This context is captured unchanged from an actual native turn. A
        // transcript interaction is not required for its real work authority.
        assert!(context.interaction_lineage_id().is_none());
        assert!(context.work_authorization().is_some());
        assert!(context.retained_work().is_some());
        assert_eq!(context.origin_session_id(), Some(&fixture.session));
        let resolved = fixture.source.acquisition_original(&context).await.unwrap();
        let exact_binding = fixture.binding().await.unwrap().unwrap();
        assert_eq!(resolved.original.association(), &exact_binding);
        assert_eq!(fixture.source.binding_evidence(&resolved.reference).await.unwrap().as_ref(),
            Some(&exact_binding));
        // Removing actual native authority cannot borrow identity from an
        // absent transcript interaction, and a different session cannot reuse
        // the unchanged work scope. Neither negative enters setup admission.
        let missing_authority = context.clone().with_work_authorization(None);
        assert!(matches!(fixture.source.acquisition_original(&missing_authority).await,
            Err(crate::private_originals::PrivateOriginalError::Unavailable)));
        let wrong_session = context.clone().with_runtime_identity(meerkat_core::SessionId::new(), None);
        assert!(matches!(fixture.source.acquisition_original(&wrong_session).await,
            Err(crate::private_originals::PrivateOriginalError::Denied)));
        let valid_request = RawValue::from_string(r#"{"request":"Find a tool for the original request"}"#.into()).unwrap();
        assert!(matches!(tools.acquisition_tool().dispatch_with_context(ToolCallView {
            id: "missing-work-authority", name: crate::FIND_AND_INSTALL, args: &valid_request,
        }, &missing_authority).await, Err(ToolError::AccessDenied { .. })));
        assert!(matches!(tools.acquisition_tool().dispatch_with_context(ToolCallView {
            id: "wrong-work-session", name: crate::FIND_AND_INSTALL, args: &valid_request,
        }, &wrong_session).await, Err(ToolError::AccessDenied { .. })));
        // The real native context reaches the production parser. The former
        // unconditional refusal cannot satisfy this assertion. No protocol-only
        // admission entry, synthetic authorization or native tool grant is used.
        let malformed = RawValue::from_string("{}".into()).unwrap();
        let malformed_result = tools.acquisition_tool().dispatch_with_context(ToolCallView {
            id: "actual-bound-parser", name: crate::FIND_AND_INSTALL, args: &malformed,
        }, &context).await;
        let result_kind = match &malformed_result {
            Ok(_) => "Ok",
            Err(ToolError::InvalidArguments { .. }) => "Err(InvalidArguments)",
            Err(ToolError::AccessDenied { .. }) => "Err(AccessDenied)",
            Err(ToolError::Unavailable { .. }) => "Err(Unavailable)",
            Err(ToolError::NotFound { .. }) => "Err(NotFound)",
            Err(_) => "Err(other ToolError)",
        };
        let error_discriminant = malformed_result.as_ref().err().map(std::mem::discriminant);
        assert!(matches!(&malformed_result, Err(ToolError::InvalidArguments { .. })),
            "expected InvalidArguments; result={result_kind}, error_discriminant={error_discriminant:?}, origin_session_present={}, interaction_lineage_present={}, work_authorization_present={}, retained_work_present={}, run_id_present={}",
            context.origin_session_id().is_some(), context.interaction_lineage_id().is_some(),
            context.work_authorization().is_some(), context.retained_work().is_some(),
            context.run_id().is_some());
        // The probe captured this context during plan resolution, before the
        // native dispatcher prepared authorization for any tool body. Calling
        // a report leaf with it must fail at that native call boundary.
        let report = RawValue::from_string(r#"{"kind":"failed","detail":"No tool is installed by this control"}"#.into()).unwrap();
        let report_result = tools.result_tool().dispatch_with_context(ToolCallView {
            id: "not-the-helper", name: meerkat_toolkit::setup::SETUP_REPORT, args: &report,
        }, &context).await;
        let report_refusal_kind = match &report_result {
            Err(ToolError::AuthorizationRefused { refusal }) => Some(refusal.kind()),
            _ => None,
        };
        assert!(matches!(&report_result,
            Err(ToolError::AuthorizationRefused { refusal })
                if refusal.kind() == meerkat_core::authorization::OperationRefusalKind::MalformedFacts),
            "pre-execution context must refuse native report authorization; result_is_ok={}, error_discriminant={:?}, native_refusal_kind={report_refusal_kind:?}",
            report_result.is_ok(), report_result.as_ref().err().map(std::mem::discriminant));
        // Independently exercise the real helper-source owner: an original
        // input cannot substitute for helper custody merely because both
        // production leaves retain the same installed acquisition owner.
        let helper_source = fixture.source.setup_result_source(&context, &owner.helper).await;
        assert!(matches!(&helper_source, Err(crate::private_originals::PrivateOriginalError::Denied)),
            "original input must not supply helper source custody; result_is_ok={}, error_discriminant={:?}",
            helper_source.is_ok(), helper_source.as_ref().err().map(std::mem::discriminant));
        let request = RawValue::from_string(r#"{"request":"Find a tool for the original request"}"#.into()).unwrap();
        assert!(matches!(tools.acquisition_tool().dispatch_with_context(ToolCallView {
            id: "missing-continuation", name: crate::FIND_AND_INSTALL, args: &request,
        }, &context).await, Err(ToolError::Unavailable { .. })),
            "actual original_task must refuse its unbound native continuation before admission");
        let scope = toolkit_store::StoreScope { realm: owner.host.tenant.to_string(),
            owner: format!("toolkit/acquisition/{}", owner.host.deployment) };
        assert!(owner.store.list_records(&scope, None, 10).await.unwrap().is_empty());
        assert_eq!(fixture.inputs().await.unwrap(), before_inputs);
        assert_eq!(fixture.model_requests(), before_requests);
        fixture.lifetime().begin_close_activation(HostCloseReason::Shutdown).unwrap();
        assert!(tools.0.binding.execution_owner().is_none());
        assert!(matches!(tools.acquisition_tool().dispatch_with_context(ToolCallView {
            id: "closed-native", name: crate::FIND_AND_INSTALL, args: &malformed,
        }, &context).await, Err(ToolError::Unavailable { .. })));
        assert!(matches!(tools.result_tool().dispatch_with_context(ToolCallView {
            id: "closed-native-report", name: meerkat_toolkit::setup::SETUP_REPORT, args: &report,
        }, &context).await, Err(ToolError::Unavailable { .. })));
    })).catch_unwind().await;
    let cleanup = fixture.shutdown().await;
    assert!(cleanup.is_ok(), "{cleanup:?}");
    if let Err(panic) = result { std::panic::resume_unwind(panic); }
}
