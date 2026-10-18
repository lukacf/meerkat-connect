//! A fresh full roster through the real held bootstrap. The selected member
//! names are test inputs, not a production singleton or an online append API.
use super::*;
use meerkat_toolkit::setup::{SetupWorkBackend, SetupWorkContext, SetupWorkflowTerms};
use meerkat_workgraph::{WorkGraphService, SqliteWorkGraphStore, WorkNamespace,
    CreateWorkItemRequest, ClaimWorkItemRequest, WorkOwner, WorkOwnerKey,
    LinkWorkItemsRequest, WorkEdgeKind, WorkItemRef};
use meerkat_authorization_contracts::constraints::{DelegationDepth, LifetimeRestriction};
use toolkit_package::{ContentDigest, Revision};
use meerkat_mobkit::rpc_gateway::GatewayHostComposition;

pub(in crate::private_originals) struct DedicatedFixture {
    pub f: FirstFixture,
    pub member: Arc<crate::private_originals::InstalledWorkflowMember>,
    pub parent: PrivateOriginalSubmit,
    pub lead: PrivateOriginalSubmit,
    pub terms: SetupWorkflowTerms,
    pub lineage: Vec<GrantLineageRef>,
    pub backend: SetupWorkBackend,
    pub work: SetupWorkContext,
    pub parent_session: SessionId,
    pub lead_session: SessionId,
    _gateway: crate::host_gateway::ToolkitGatewayHost,
    _private_open: tokio::sync::watch::Sender<bool>,
}
async fn event(source: &Arc<PrivateOriginals>, route: &str, label: &str, contributors: Vec<EvidenceId>) -> PrivateOriginalSubmit {
    let mut event = private_event(label);
    event.route = Id::new(route).unwrap();
    event.content_sha256 = digest(label.as_bytes());
    event.contributors = contributors;
    let authentication = event.original_authentication.clone();
    let original = source.retain_event(event).await.unwrap();
    PrivateOriginalSubmit { original, content: label.into(), transport_authentication: authentication }
}
fn work_ref(item: &meerkat_workgraph::WorkItem) -> WorkItemRef {
    WorkItemRef { realm_id: item.realm_id.clone(), namespace: item.namespace.clone(), item_id: item.id.clone() }
}
async fn claimed(service: &WorkGraphService, label: &str) -> meerkat_workgraph::WorkItem {
    let item = service.create(CreateWorkItemRequest { title: label.into(), labels: ["dedicated-cycle".into()].into(), ..Default::default() }).await.unwrap();
    service.claim(ClaimWorkItemRequest { id: item.id, realm_id: None, namespace: None,
        expected_revision: item.revision,
        owner: WorkOwner { key: WorkOwnerKey::agent(label).unwrap(), display_name: None },
        lease_seconds: Some(300), lease_expires_at: None,
    }).await.unwrap()
}
impl DedicatedFixture {
    pub async fn new() -> Self { Self::with_participant(true).await }
    pub async fn without_participant() -> Self { Self::with_participant(false).await }
    async fn with_participant(capture_workflow: bool) -> Self {
        let mut opened = None;
        let mut retained = None;
        let result = std::panic::AssertUnwindSafe(Self::build(&mut opened, &mut retained, capture_workflow)).catch_unwind().await;
        match result {
            Ok(result) => result,
            Err(panic) => {
                let cleanup = match &opened { Some(native) => shutdown_fixture(native).await, None => Ok(()) };
                drop(retained);
                assert!(cleanup.is_ok(), "{cleanup:?}");
                std::panic::resume_unwind(panic)
            }
        }
    }
    async fn build(opened: &mut Option<UnifiedRuntime>, retained: &mut Option<(Arc<tempfile::TempDir>, Arc<NativeHostLifetime>)>, capture_workflow: bool) -> Self {
        let facts = meerkat_core::ControllerModelFacts::new(selection(), ENDPOINT.into(), MODEL.into());
        let mut host = crate::installed_host::controller_first_input_fixture::open_for_dedicated_workflow(&facts).await;
        *retained = Some((host.directory.clone(), host.lifetime.clone()));
        let source = host.originals.clone();
        assert!(source.host_lifetime.get().is_none(), "the dedicated fixture must not prebind a private lifetime");
        let (private_open, private_closed) = tokio::sync::watch::channel(false);
        let other_lifetime = Arc::new(NativeHostLifetime::bootstrap(host.selection.clone()).unwrap());
        let competing = host.competing_gateway(other_lifetime.clone(),
            crate::private_host::PrivateHostClosed(private_closed.clone()));
        let same_host_without_participant = (!capture_workflow).then(|| host.competing_gateway(
            host.lifetime.clone(), crate::private_host::PrivateHostClosed(private_closed.clone())));
        let mut gateway = host.installed.take().unwrap().compose(
            host.lifetime.clone(), crate::private_host::PrivateHostClosed(private_closed));
        let parent = event(&source, "planning_parent", "dedicated parent request", vec![]).await;
        let lead = event(&source, "planning_lead", "dedicated planning request", vec![parent.original.original.clone()]).await;
        let submission = event(&source, "console", PROMPT, vec![]).await;
        let selected = host.lifetime.selected_policy().native_host.as_ref().unwrap();
        let route = source.route(&lead.original.route).unwrap();
        let member_selection = selected.members.iter().find(|m| m.member.member == "planning_lead").unwrap();
        let now = source.owner.clock().now().unwrap().unix_ms;
        let deadline = now + 180_000;
        let bounds = ExecutionRestrictions { delegation_depth: DelegationDepth::remaining(1),
            lifetime: LifetimeRestriction::window(now, deadline + 60_000), ..ExecutionRestrictions::unrestricted() };
        let root = source.owner.grants().issue_root(
            &meerkat::governed_realm::stock::StockPrincipals::for_local_operator(&selected.realm).unwrap().operator,
            EvidenceId::new("dedicated-operation-root").unwrap(), selected.grant_administrator.clone(),
            route.represented_subject.clone(), bounds.clone(),
        ).unwrap();
        let child = bounds.for_child(&ExecutionRestrictions { delegation_depth: DelegationDepth::remaining(0), ..ExecutionRestrictions::unrestricted() }).unwrap();
        let leaf = source.owner.grants().issue_child(&selected.grant_administrator, &root,
            EvidenceId::new("dedicated-operation-leaf").unwrap(), route.logical_executor.clone(), child.clone()).unwrap();
        let lineage = vec![root, leaf];
        let graph = WorkGraphService::with_scope(Arc::new(SqliteWorkGraphStore::open(host.source_path.with_extension("dedicated-work.sqlite")).unwrap()),
            host.source_scope.realm.clone(), WorkNamespace::new("dedicated-workflow").unwrap());
        let parent_work = claimed(&graph, "parent").await;
        let waiter_work = claimed(&graph, "waiter-a").await;
        graph.link(LinkWorkItemsRequest { realm_id: None, namespace: None, kind: WorkEdgeKind::Parent,
            from_id: waiter_work.id.clone(), to_id: parent_work.id.clone() }).await.unwrap();
        let backend = SetupWorkBackend::new(graph, "dedicated-sqlite".into(), Id::new("one").unwrap(),
            &[meerkat_core::DurabilityDeclaration::durable("workgraph", meerkat_core::DurabilityResolution::Persistent)]).unwrap();
        let work = SetupWorkContext::from_owner(backend.pin().clone(), work_ref(&parent_work), work_ref(&waiter_work),
            parent_work.owner.as_ref().unwrap().key.clone(), waiter_work.owner.as_ref().unwrap().key.clone(), "dedicated-cycle".into()).unwrap();
        let terms = SetupWorkflowTerms { key: Id::new("dedicated-workflow").unwrap(), backend: backend.pin().clone(),
            parent: work_ref(&parent_work), parent_owner: parent_work.owner.as_ref().unwrap().key.clone(), cycle_label: "dedicated-cycle".into(),
            requester: route.requester.clone(), realm: route.realm.clone(), authority_revision: Revision::new("dedicated-policy").unwrap(),
            planning_source: source.source_record_key(&lead.original).await.unwrap(), lead: member_selection.member.clone(),
            envelope_digest: ContentDigest::of_bytes(&canonical_json(&child).unwrap()), deadline_ms: deadline, max_waiters: 8 };
        let roster: Vec<_> = [MEMBER, "planning_parent", "planning_lead"].into_iter().map(|name| DurableAgentSpec {
            identity: AgentIdentity::parse(name).unwrap(), profile: ProfileName::from("worker"),
            addressability: if name == "planning_lead" { AgentAddressability::InternalOnly } else { AgentAddressability::Addressable },
            display_name: None, labels: BTreeMap::new(), context: None, additional_instructions: vec![], initial_message: None,
            runtime_mode_override: Some(MobRuntimeMode::TurnDriven), backend: None, binding: None, placement: None,
        }).collect();
        let mut wrong_spec = roster[2].clone();
        wrong_spec.addressability = AgentAddressability::Addressable;
        assert!(gateway.reserve_workflow_member(&terms, &lead.original, &wrong_spec).await.is_err());
        assert!(source.host_lifetime.get().is_none(), "a rejected reservation cannot freeze a host lifetime");
        let member = gateway.reserve_workflow_member(&terms, &lead.original, &roster[2]).await.unwrap();
        assert!(Arc::ptr_eq(&source.host_lifetime.get().and_then(std::sync::Weak::upgrade).unwrap(), &host.lifetime),
            "successful reservation selects the exact host before any capture");
        assert!(member.session().is_err(), "a selection is not a native session");
        let same_member = gateway.reserve_workflow_member(&terms, &lead.original, &roster[2]).await.unwrap();
        assert!(same_member.session().is_err(), "public exact replay does not create or capture a member");
        assert!(Arc::ptr_eq(&source.host_lifetime.get().and_then(std::sync::Weak::upgrade).unwrap(), &host.lifetime),
            "public replay confirms the existing exact host lifetime");
        let configuration = gateway.native_grant_work_configuration().unwrap().unwrap();
        let machine = Arc::new(MeerkatMachine::ephemeral().with_local_grant_authorization(configuration).unwrap());
        let provider = Arc::new(ScriptedProvider::default());
        let probe = Arc::new(crate::installed_host::acquisition::ContextProbe::default());
        let custody = meerkat_mobkit::MemberMcpCustody::new();
        let mut builder = FactoryAgentBuilder::new(custody.install(AgentFactory::minimal().comms(true)), Config::default());
        builder.default_llm_client = Some(Arc::new(crate::installed_host::acquisition::ProbeProvider::with_probe(provider.clone(), &probe)));
        *builder.default_agent_llm_client_decorator.write().unwrap() = Some(fixture_controller_decorator());
        builder.default_session_store = Some(Arc::new(SessionStore::default()));
        let service = Arc::new(EphemeralSessionService::new(builder, 4));
        let mut definition = definition(); definition.id = MobId::from("factory");
        let ProfileBinding::Inline(profile) = definition.profiles.get_mut(&ProfileName::from("worker")).unwrap() else { panic!("inline") };
        profile.tools = ToolConfig { comms: true, ..Default::default() };
        let competing_spec = MobBootstrapSpec::new(definition.clone(), MobStorage::in_memory(), service.clone())
            .with_session_runtime_adapter(machine.clone()).unwrap().with_declared_ephemeral_mob_storage();
        assert!(matches!(competing.prepare_bootstrap(competing_spec).await,
            Err(meerkat_mobkit::rpc_gateway::GatewayHostError::Denied)),
            "a different host cannot bind the reserved source before its registration captures G");
        assert!(Arc::ptr_eq(&source.host_lifetime.get().and_then(std::sync::Weak::upgrade).unwrap(), &host.lifetime));
        assert!(source.machine().is_err(), "the losing bootstrap cannot bind the source machine");
        assert!(member.session().is_err(), "the losing bootstrap cannot materialize or capture a member");
        drop(competing);
        drop(other_lifetime);
        // The negative mode uses a second public composition over the SAME
        // lifetime/source, with the real registration but no workflow observer.
        // No source selection or actual native destination is fabricated.
        if let Some(without_participant) = same_host_without_participant {
            gateway = without_participant;
        }
        let tool_probe = probe.clone();
        let spec = MobBootstrapSpec::new(definition, MobStorage::in_memory(), service.clone())
            .with_session_runtime_adapter(machine.clone()).unwrap().with_member_mcp_custody(custody)
            .with_declared_ephemeral_mob_storage().with_default_external_tools_provider(Arc::new(move || Some(tool_probe.clone() as Arc<dyn meerkat_core::AgentToolDispatcher>)));
        let spec = gateway.prepare_bootstrap(spec).await.unwrap();
        assert!(Arc::ptr_eq(&source.host_lifetime.get().and_then(std::sync::Weak::upgrade).unwrap(), &host.lifetime));
        assert!(gateway.reserve_workflow_member(&terms, &lead.original, &roster[2]).await.is_err(),
            "materialization cannot accept a new late registration participant");
        *opened = Some(bootstrap_fixture(spec, "factory".into()).await);
        let native = opened.as_mut().unwrap();
        let handle = native.mob_handle();
        let bridge = MobSessionBridge::with_session_service(handle.clone(), native.mob_runtime().session_service().cloned().unwrap())
            .with_controller_pin_source(service.clone());
        let runtime = Arc::new(IdentityRuntime::new(IdentityRuntimeConfig {
            continuity_store: Arc::new(LocalContinuityStore::in_memory().unwrap()), lease_provider: Arc::new(LocalLeaseProvider::new()),
            runtime_instance_id: "dedicated-workflow-test".into(), has_runtime_store: true, durability_policy: DurabilityPolicy::SyncWriteThrough,
            bridge: Some(Arc::new(bridge)), default_timeout: None,
        }).with_runtime_services(meerkat_mobkit::identity_first::AgentRuntimeServices::new(handle.clone())));
        let context = Arc::new(IdentityFirstRuntimeContext::new(runtime,
            Arc::new(MutableRosterProvider::new(roster.clone())), None, None, Some(handle.definition().clone())));
        native.attach_identity_first_context(context.clone());
        let runtime = native.identity_runtime().unwrap();
        gateway.bind_runtime(native).await.unwrap();
        gateway.bind_identity_runtime(native).await.unwrap();
        let complete_member = member.clone();
        let result = context.bootstrap_roster_held(&roster, tokio::time::Instant::now() + Duration::from_secs(30), move |members, _completion| async move {
            let held = members.iter().find(|row| row.identity.as_str() == "planning_lead").ok_or("missing actual G")?;
            if capture_workflow { complete_member.complete_held_member(held).await.map_err(|error| error.to_string()) }
            else { Ok(()) }
        }).await.unwrap();
        match result {
            meerkat_mobkit::identity_first::HeldBootstrapStart::Activated(_) => (),
            meerkat_mobkit::identity_first::HeldBootstrapStart::Unsettled(settlement) => {
                let _actual = settlement.settled().await;
                panic!("held full-roster construction did not activate")
            }
        }
        let mut sessions = Vec::new();
        for row in &roster {
            let status = runtime.status(&row.identity).await.unwrap();
            assert_eq!(status.state, IdentityLifecycleState::Active);
            sessions.push(status.session_id.unwrap());
        }
        assert!(sessions[0] != sessions[1] && sessions[0] != sessions[2] && sessions[1] != sessions[2]);
        if capture_workflow { assert_eq!(member.session().unwrap(), sessions[2]); }
        else { assert!(member.session().is_err(), "omitting the participant cannot manufacture capture"); }
        let actor = service.live_session_actor_witness(&sessions[2]).await.unwrap();
        let pin = service.pin_controller_client_for_actor(&actor).await.unwrap();
        meerkat_core::publish_token_lifecycle_acquired_for_identity_within(&machine.generated_auth_lease_handle(), pin.selection().credential(),
            &meerkat_core::auth::PersistedTokens::api_key("synthetic-controller-only-fixture"), tokio::time::Instant::now() + WAIT).await.unwrap();
        let f = FirstFixture { store: host.store, source_path: host.source_path, scope: host.source_scope,
            service, probe: Some(probe), _directory: host.directory, _lifetime: host.lifetime, source,
            machine, native: opened.take().unwrap(), runtime, identity: roster[0].identity.clone(), session: sessions[0].clone(), provider, submission };
        Self { f, member, parent, lead, terms, lineage, backend, work,
            parent_session: sessions[1].clone(), lead_session: sessions[2].clone(),
            _gateway: gateway, _private_open: private_open }
    }
}
