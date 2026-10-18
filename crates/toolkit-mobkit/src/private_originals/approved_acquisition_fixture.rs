//! Approved setup uses the existing persistent first-input fixture composition.
//! Delivery and continuation are the real selected bootstrap owners; no fixture
//! constructs a replacement ContinuationOwnerService or borrows a prior turn.
use super::*;

impl FirstFixture<meerkat::PersistentSessionService<FactoryAgentBuilder>> {
    pub(super) async fn for_approved_acquisition(
        script: Arc<acquisition_denial::Script>,
    ) -> (Self, Arc<dyn meerkat_runtime::RuntimeStore>) {
        Self::for_acquisition_mode(script, None, false, None, None, None, None).await
    }

    pub(super) async fn for_helper_report(
        script: Arc<acquisition_denial::Script>,
        report: Arc<helper_report::Report>,
    ) -> (Self, Arc<dyn meerkat_runtime::RuntimeStore>) {
        Self::for_acquisition_mode(script, Some(report), false, None, None, None, None).await
    }

    pub(super) async fn for_configured_helper_report(
        script: Arc<acquisition_denial::Script>,
        report: Arc<helper_report::Report>,
    ) -> (Self, Arc<dyn meerkat_runtime::RuntimeStore>) {
        Self::for_acquisition_mode(script, Some(report), true, None, None, None, None).await
    }

    pub(super) async fn for_warm_helper_report(
        script: Arc<acquisition_denial::Script>, report: Arc<helper_report::Report>,
    ) -> (Self, Arc<dyn meerkat_runtime::RuntimeStore>) {
        Self::for_warm_helper_profile(script, report,
            crate::installed_host::controller_first_input_fixture::WarmHelperProfile::Standard).await
    }

    pub(super) async fn for_warm_helper_profile(
        script: Arc<acquisition_denial::Script>, report: Arc<helper_report::Report>,
        profile: crate::installed_host::controller_first_input_fixture::WarmHelperProfile,
    ) -> (Self, Arc<dyn meerkat_runtime::RuntimeStore>) {
        Self::for_acquisition_mode(script, Some(report), true, None, None, Some(profile), None).await
    }

    pub(super) async fn for_warm_helper_report_with_provider(
        script: Arc<acquisition_denial::Script>, report: Arc<helper_report::Report>,
        decorate: Arc<dyn Fn(Arc<dyn LlmClient>) -> Arc<dyn LlmClient> + Send + Sync>,
    ) -> (Self, Arc<dyn meerkat_runtime::RuntimeStore>) {
        Self::for_acquisition_mode(script, Some(report), true, None, None,
            Some(crate::installed_host::controller_first_input_fixture::WarmHelperProfile::Standard),
            Some(decorate)).await
    }

    pub(super) async fn for_helper_entry(
        script: Arc<acquisition_denial::Script>,
        fault: Arc<DeliveryFault>,
    ) -> (Self, Arc<dyn meerkat_runtime::RuntimeStore>) {
        assert!(matches!(fault.mode,
            DeliveryMode::HoldHelperBeforeLookup | DeliveryMode::HoldHelperAcceptedReply)
            || fault.mode.helper_reprepare());
        Self::for_acquisition_mode(script, None, false, Some(fault), None, None, None).await
    }

    pub(super) async fn for_catalog_successor(
        script: Arc<acquisition_denial::Script>,
        catalog: Arc<helper_entry_native::CatalogProbe>,
    ) -> (Self, Arc<dyn meerkat_runtime::RuntimeStore>) {
        Self::for_acquisition_mode(script, None, false, None, Some(catalog), None, None).await
    }

    async fn for_acquisition_mode(
        script: Arc<acquisition_denial::Script>,
        report: Option<Arc<helper_report::Report>>,
        configured_report: bool,
        fault: Option<Arc<DeliveryFault>>,
        catalog: Option<Arc<helper_entry_native::CatalogProbe>>,
        warm_report: Option<crate::installed_host::controller_first_input_fixture::WarmHelperProfile>,
        warm_provider: Option<Arc<dyn Fn(Arc<dyn LlmClient>) -> Arc<dyn LlmClient> + Send + Sync>>,
    ) -> (Self, Arc<dyn meerkat_runtime::RuntimeStore>) {
        let mut opened = None;
        let mut owners = None;
        let built = std::panic::AssertUnwindSafe(tokio::time::timeout(
            WAIT,
            Box::pin(Self::build_approved_acquisition(
                script,
                report,
                configured_report,
                fault,
                catalog,
                warm_report,
                warm_provider,
                &mut opened,
                &mut owners,
            )),
        ))
        .catch_unwind()
        .await;
        match built {
            Ok(Ok(fixture)) => fixture,
            failed => {
                let cleanup = match opened {
                    Some(runtime) => shutdown_fixture(&runtime).await,
                    None => Ok(()),
                };
                drop(owners);
                assert!(cleanup.is_ok(), "{cleanup:?}");
                match failed {
                    Err(payload) => std::panic::resume_unwind(payload),
                    _ => panic!("persistent first-input fixture construction timed out"),
                }
            }
        }
    }

    async fn build_approved_acquisition(
        script: Arc<acquisition_denial::Script>,
        report: Option<Arc<helper_report::Report>>,
        configured_report: bool,
        fault: Option<Arc<DeliveryFault>>,
        catalog: Option<Arc<helper_entry_native::CatalogProbe>>,
        warm_report: Option<crate::installed_host::controller_first_input_fixture::WarmHelperProfile>,
        warm_provider: Option<Arc<dyn Fn(Arc<dyn LlmClient>) -> Arc<dyn LlmClient> + Send + Sync>>,
        opened: &mut Option<UnifiedRuntime>,
        owners: &mut Option<(Arc<tempfile::TempDir>, Arc<NativeHostLifetime>)>,
    ) -> (Self, Arc<dyn meerkat_runtime::RuntimeStore>) {
        let facts =
            meerkat_core::ControllerModelFacts::new(selection(), ENDPOINT.into(), MODEL.into());
        use crate::installed_host::controller_first_input_fixture as installed;
        assert!(!configured_report || report.is_some());
        let private_helper_entry = fault.is_some() || catalog.is_some();
        assert!(catalog.is_none() || fault.is_none());
        assert!(!private_helper_entry || (report.is_none() && !configured_report));
        assert!(warm_report.is_none() || (configured_report && report.is_some()));
        assert!(warm_provider.is_none() || warm_report.is_some());
        let mut host = match &report {
            Some(report) if warm_report.is_some() => installed::open_for_warm_helper_profile(
                &facts, script.dispatcher(), report.dispatcher(), warm_report.unwrap(),
            ).await,
            Some(report) if configured_report => installed::open_for_configured_helper_report(
                &facts, script.dispatcher(), report.dispatcher(),
            ).await,
            Some(report) => installed::open_for_helper_report(
                &facts, script.dispatcher(), report.dispatcher(),
            ).await,
            None => installed::open_for_acquisition(&facts, script.dispatcher(), private_helper_entry, catalog.is_some()).await,
        };
        *owners = Some((host.directory.clone(), host.lifetime.clone()));
        // Only the original direct-grant report mode waits until spawn. The
        // configured-parent mode binds the actual installed owner now, before
        // session preparation, with no final report child in its operation basis.
        let pending = ((report.is_some() && !configured_report) || catalog.is_some())
            .then(|| installed::prepare_approved_acquisition(&host));
        if configured_report {
            report.as_ref().unwrap().retain_selection(host.acquisition_helper.clone().unwrap());
        }
        let (continuation, workgraph) = match &pending {
            Some(ports) => (ports.continuation.clone(), ports.workgraph.clone()),
            None => {
                let ports = installed::prepare_approved_acquisition(&host);
                let owner = ports.bind_with_limits(script.tools(),
                    host.acquisition_helper.clone().unwrap(), script.setup_limits());
                script.retain_owner(owner);
                (ports.continuation, ports.workgraph)
            }
        };
        let provider = Arc::new(ScriptedProvider::default());
        let mut builder =
            FactoryAgentBuilder::new(AgentFactory::minimal().comms(true), Config::default());
        let client = script.provider(provider.clone());
        let client = match &catalog { Some(probe) => probe.provider(client), None => client };
        let client = match &report {
            Some(report) => report.provider(client),
            None => client,
        };
        builder.default_llm_client = Some(match warm_provider {
            Some(decorate) => decorate(client),
            None => client,
        });
        let runtime_store: Arc<dyn meerkat_runtime::RuntimeStore> =
            Arc::new(meerkat_runtime::InMemoryRuntimeStore::new());
        let mob_tools = builder.default_mob_tools.clone();
        *builder.default_agent_llm_client_decorator.write().unwrap() =
            Some(fixture_controller_decorator());
        if let Some(fault) = fault.as_ref().filter(|fault| fault.mode.helper_reprepare()) {
            host.configuration.operation_owner = Arc::new(observed::AdmissionChangingOwner {
                inner: host.configuration.operation_owner.clone(),
                fault: fault.clone(),
                publication: host.originals.owner.publication(),
            });
        }
        // Select the governed persistent machine before publishing any adapter.
        // The facade wires the SAME stores into the factory and concrete service.
        let persistence = meerkat::PersistenceBundle::new_with_local_grant_authorization(
            Arc::new(
                meerkat::SqliteSessionStore::open(
                    host.directory.path().join("native-sessions.sqlite3"),
                )
                .unwrap(),
            ),
            runtime_store.clone(),
            Arc::new(meerkat::MemoryBlobStore::new()),
            host.configuration,
        )
        .unwrap();
        // The facade installs this exact job store in the factory. The Meta
        // delivery below retains it too; an independent fixture store is not used.
        let jobs = persistence.job_store();
        let (service, machine) =
            meerkat::surface::build_runtime_backed_service(builder, 4, persistence)
                .expect("compose approved acquisition runtime");
        let service = Arc::new(service);
        let mut definition = definition();
        definition.id = MobId::from("factory");
        let ProfileBinding::Inline(profile) = definition
            .profiles
            .get_mut(&ProfileName::from("worker"))
            .unwrap()
        else {
            panic!("inline fixture")
        };
        profile.tools = ToolConfig {
            comms: true,
            ..Default::default()
        };
        let namespace = definition.id.to_string();
        profile
            .tools
            .rust_bundles
            .push(crate::FIND_AND_INSTALL_BUNDLE.into());
        if report.is_some() || private_helper_entry {
            let mut helper = profile.clone();
            let helper_profile = if private_helper_entry {
                helper.external_addressable = false;
                installed::PRIVATE_HELPER_PROFILE
            } else {
                helper.tools.rust_bundles = vec![meerkat_toolkit::setup::SETUP_RESULTS_BUNDLE.into()];
                installed::REPORT_PROFILE
            };
            definition.profiles.insert(ProfileName::from(helper_profile), ProfileBinding::Inline(helper));
        }
        let mut spec = MobBootstrapSpec::new(definition, MobStorage::in_memory(), service.clone())
            .with_session_runtime_adapter(machine.clone())
            .unwrap()
            .with_member_runtime_registration_hook(host.registration)
            .with_tool_consequence_policy_registry(host.tool_policy_registry)
            .with_declared_ephemeral_mob_storage()
            .with_workgraph_service(Some(workgraph))
            .with_runtime_delivery(meerkat_mobkit::mob_handle_runtime::MobRuntimeDelivery::new(
                runtime_store.clone(),
                jobs,
            ))
            .with_agent_mob_tools(mob_tools)
            .unwrap()
            .with_host_job_source(
                meerkat_mob_mcp::HostJobSource::new(
                    [continuation.namespace().to_owned()],
                    continuation.clone(),
                )
                .unwrap(),
            )
            .unwrap()
            .register_tool_bundle(crate::FIND_AND_INSTALL_BUNDLE, script.dispatcher());
        if let Some(report) = &report {
            spec = spec.register_tool_bundle(meerkat_toolkit::setup::SETUP_RESULTS_BUNDLE, report.dispatcher());
        }
        *opened = Some(bootstrap_fixture(spec, namespace).await);
        let native = opened.as_mut().unwrap();
        continuation.bind_native(native.mob_runtime()).unwrap();
        let handle = native.mob_handle();
        let member = MemberIdentity::from(MEMBER);
        let identity = AgentIdentity::parse(MEMBER).unwrap();
        // Match Meta's normal bridge labels so the identity completion monitor
        // can attribute events from these manually materialized members.
        handle
            .spawn_spec(SpawnMemberSpec::new("worker", member.clone()).with_labels(BTreeMap::from([
                ("agent_identity".to_owned(), identity.as_str().to_owned()),
                ("profile_name".to_owned(), "worker".to_owned()),
            ])))
            .await
            .unwrap();
        let session = handle
            .get_member(&member)
            .await
            .unwrap()
            .unwrap()
            .bridge_session_id()
            .cloned()
            .unwrap();
        let lease = service
            .acquire_live_session_actor_turn_boundary_lease(&session)
            .await
            .unwrap();
        let pin = service
            .pin_controller_client_for_actor(&lease)
            .await
            .unwrap();
        drop(lease);
        assert_eq!(pin.selection(), &selection());
        // Native startup may briefly hold controller custody. The existing
        // bounded owner helper retries only typed Busy and rechecks references;
        // no input is submitted until this actual publication succeeds.
        meerkat_core::publish_token_lifecycle_acquired_for_identity_within(
            &machine.generated_auth_lease_handle(),
            pin.selection().credential(),
            &meerkat_core::auth::PersistedTokens::api_key("synthetic-controller-only-fixture"),
            tokio::time::Instant::now() + WAIT,
        )
        .await
        .expect("selected fixture credential publishes within its setup deadline");
        let helper_member =
            MemberIdentity::from(crate::installed_host::controller_first_input_fixture::HELPER);
        let helper =
            AgentIdentity::parse(crate::installed_host::controller_first_input_fixture::HELPER)
                .unwrap();
        let helper_profile = if report.is_some() { installed::REPORT_PROFILE }
            else if private_helper_entry { installed::PRIVATE_HELPER_PROFILE } else { "worker" };
        let helper_session = if configured_report {
            assert!(handle.get_member(&helper_member).await.unwrap().is_none());
            None
        } else {
            handle
                .spawn_spec(SpawnMemberSpec::new(helper_profile, helper_member.clone()).with_labels(BTreeMap::from([
                    ("agent_identity".to_owned(), helper.as_str().to_owned()),
                    ("profile_name".to_owned(), helper_profile.to_owned()),
                ])))
                .await
                .unwrap();
            let helper_session = handle
                .get_member(&helper_member)
                .await
                .unwrap()
                .unwrap()
                .bridge_session_id()
                .cloned()
                .unwrap();
            Some(helper_session)
        };
        if let (Some(ports), Some(report)) = (&pending, &report) {
            let native = host.lifetime.selected_policy().native_host.as_ref().unwrap();
            let mut helper = host.acquisition_helper.clone().unwrap();
            let member = native.members.iter().find(|member| member.member == helper.member).unwrap();
            let mut restrictions = crate::installed_host::application_operations::parent_restrictions(
                crate::installed_host::application_operations::setup_report(
                    &native.grant_administrator, &helper.logical_executor, &member.audience, helper_session.as_ref().unwrap(),
                ),
            );
            restrictions.delegation_depth = meerkat_authorization_contracts::constraints::DelegationDepth::remaining(0);
            let operator = meerkat::governed_realm::stock::StockPrincipals::for_local_operator(&native.realm).unwrap().operator;
            let grant = host.originals.owner.grants().issue_root(
                &operator, meerkat_authorization_contracts::evidence::EvidenceId::new("fixture-helper-report").unwrap(),
                helper.logical_executor.clone(), None, restrictions,
            ).unwrap();
            helper.operation_basis = meerkat_authorization_contracts::work_association::WorkAuthorityBasis::GrantLineage { lineage: vec![grant] };
            report.retain_selection(helper.clone());
            let owner = ports.bind(script.tools(), helper);
            script.retain_owner(owner);
        }
        if let Some(probe) = &catalog {
            use crate::installed_host::{acquisition::ConfiguredHelperCatalogCapability, application_operations};
            let native = host.lifetime.selected_policy().native_host.as_ref().unwrap();
            let mut helper = host.acquisition_helper.clone().unwrap();
            let member = native.members.iter().find(|row| row.member == helper.member).unwrap();
            let operator = meerkat::governed_realm::stock::StockPrincipals::for_local_operator(&native.realm)
                .unwrap().operator;
            // Both cases explicitly select catalog authority before the owner
            // binds. The legacy case retains the actual initial session leaf;
            // opt-in selects an application parent for exact successor children.
            let (grantee, bounds) = if probe.successor {
                (native.grant_administrator.clone(),
                    application_operations::configured_catalog_parent(&helper.logical_executor, &member.audience))
            } else {
                let mut bounds = application_operations::parent_restrictions(application_operations::catalog_read(
                    &native.grant_administrator, &helper.logical_executor, &member.audience,
                    helper_session.as_ref().unwrap()));
                bounds.delegation_depth = meerkat_authorization_contracts::constraints::DelegationDepth::remaining(0);
                (helper.logical_executor.clone(), bounds)
            };
            let parent = host.originals.owner.grants().issue_root(
                &operator, EvidenceId::new("fixture-catalog-selection").unwrap(), grantee,
                helper.represented_subject.clone(), bounds).unwrap();
            if probe.successor {
                helper.catalog_capability = Some(ConfiguredHelperCatalogCapability { parent: vec![parent] });
            } else {
                helper.operation_basis = WorkAuthorityBasis::TargetedGrantLineages { base: Some(vec![parent]), targets: vec![] };
            }
            assert!(probe.selected_helper.set(helper.clone()).is_ok());
            let owner = pending.as_ref().unwrap().bind(script.tools(), helper);
            script.retain_owner(owner);
        }
        let lease_provider = Arc::new(LocalLeaseProvider::new());
        let runtime_instance = "toolkit-first-input";
        let bridge =
            MobSessionBridge::new(handle.observer()).with_controller_pin_source(service.clone());
        let bridge: Arc<dyn meerkat_mobkit::identity_first::SessionBridge> = match fault {
            Some(fault) => {
                assert!(fault.helper_session.set(helper_session.clone().unwrap()).is_ok());
                Arc::new(observed::ObservedBridge {
                    inner: bridge, fault, publication: host.originals.owner.publication(),
                })
            }
            None => Arc::new(bridge),
        };
        let runtime = Arc::new(
            IdentityRuntime::new(IdentityRuntimeConfig {
                continuity_store: Arc::new(LocalContinuityStore::in_memory().unwrap()),
                lease_provider: lease_provider.clone(),
                runtime_instance_id: runtime_instance.into(),
                has_runtime_store: true,
                durability_policy: DurabilityPolicy::SyncWriteThrough,
                bridge: Some(bridge),
                default_timeout: None,
            })
            .with_runtime_services(
                meerkat_mobkit::identity_first::AgentRuntimeServices::new(handle.clone()),
            ),
        );
        let member_spec = DurableAgentSpec {
            identity: identity.clone(),
            profile: ProfileName::from("worker"),
            addressability: AgentAddressability::Addressable,
            display_name: None,
            labels: BTreeMap::new(),
            context: None,
            additional_instructions: vec![],
            initial_message: None,
            runtime_mode_override: Some(MobRuntimeMode::TurnDriven),
            backend: None,
            binding: None,
            placement: None,
        };
        let mut helper_spec = member_spec.clone();
        helper_spec.identity = helper.clone();
        helper_spec.profile = ProfileName::from(helper_profile);
        let roster = vec![member_spec.clone(), helper_spec.clone()];
        let mut materialized = vec![(member_spec, identity.clone(), session.clone())];
        if let Some(helper_session) = helper_session {
            materialized.push((helper_spec, helper, helper_session));
        } else {
            assert!(configured_report);
            // Match Meta's lazy roster registration: the helper identity is
            // owned but has no embodiment, session or lease yet. The actual
            // governed dispatch below must still materialize it natively.
            runtime.register(helper_spec, IdentityLifecycleState::Dormant, None, None).await;
            assert_eq!(runtime.owned_identity_for_member_alias(helper.as_str()).await, Some(helper));
            assert!(handle.get_member(&helper_member).await.unwrap().is_none());
        }
        for (spec, selected_identity, selected_session) in materialized {
            let lease = lease_provider
                .acquire_leases(std::slice::from_ref(&selected_identity), runtime_instance)
                .await
                .unwrap()
                .remove(&selected_identity)
                .unwrap();
            let LeaseAcquireResult::Acquired(lease) = lease else {
                panic!("actual member identity lease refused")
            };
            runtime
                .register(
                    spec,
                    IdentityLifecycleState::Active,
                    Some(ContinuityRecord {
                        identity: selected_identity.clone(),
                        agent_runtime_id: AgentRuntimeId::parse(&format!(
                            "rt:{selected_identity}:0"
                        ))
                        .unwrap(),
                        session_id: selected_session,
                        generation: ContinuityGeneration::new(0),
                        checkpoint_version: CheckpointVersion::new(0),
                    }),
                    Some(lease),
                )
                .await;
        }
        native.attach_identity_first_context(Arc::new(IdentityFirstRuntimeContext::new(
            runtime,
            Arc::new(MutableRosterProvider::new(roster)),
            None,
            None,
            Some(handle.definition().clone()),
        )));
        let runtime = native.identity_runtime().unwrap();
        let source = host.originals;
        source.bind_machine(machine.clone()).unwrap();
        source.bind_identity_runtime(&runtime).unwrap();
        let mut event = private_event("first-conversation");
        event.route = Id::new("console").unwrap();
        event.content_sha256 = digest(PROMPT.as_bytes());
        let authentication = event.original_authentication.clone();
        let original = source.retain_event(event).await.unwrap();
        // The caller observes the same native input store used by both the
        // facade and delivery owner, including terminal rows archived out of
        // the live driver. This fixture still uses in-memory runtime storage.
        (
            Self {
                store: host.store,
                source_path: host.source_path,
                scope: host.source_scope,
                service,
                probe: None,
                _directory: host.directory,
                _lifetime: host.lifetime,
                source,
                machine,
                native: opened.take().unwrap(),
                runtime,
                identity,
                session,
                provider,
                submission: PrivateOriginalSubmit {
                    original,
                    content: PROMPT.into(),
                    transport_authentication: authentication,
                },
            },
            runtime_store,
        )
    }
}
