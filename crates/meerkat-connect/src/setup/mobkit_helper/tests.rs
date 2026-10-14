use super::*;
use meerkat_core::ops::ToolAccessPolicy;
use serde_json::json;

fn source_member() -> MobMemberBinding {
    MobMemberBinding {
        mob_id: "household".into(),
        role: "research".into(),
        member: "setup-helper".into(),
    }
}

fn helper(tools: SetupHelperTools) -> PreparedSetupHelper {
    PreparedSetupConnection::from_preparer_output(
        br#"{"mcpServers":{"toolkit-setup":{"command":"/usr/bin/python3","args":["-I","-B","/retained/setup-adapter.py"]}}}"#,
    )
    .expect("inert preparer output")
    .for_mobkit_helper(source_member(), tools)
    .expect("selected native binding")
}

fn definition() -> MobDefinition {
    serde_json::from_value(json!({
        "id": "household",
        "profiles": {
            "research": {
                "model": "claude-opus-4-8",
                "provider": "anthropic",
                "skills": ["research-method"],
                "peer_description": "Host-selected researcher",
                "tools": {
                    "builtins": true,
                    "shell": true,
                    "comms": true,
                    "memory": true,
                    "workgraph": true,
                    "read_only": false,
                    "deny": ["delete_everything"],
                    "mcp": ["browser"],
                    "mcp_servers": [{
                        "name": "reference",
                        "command": "/retained/reference-server",
                        "args": []
                    }],
                    "rust_bundles": ["trusted-research"]
                }
            }
        }
    }))
    .expect("native inline research definition")
}

#[test]
fn dedicated_profile_preserves_shared_research_and_exact_server_ceiling() {
    let selected = helper(SetupHelperTools::InertAcquisition);
    let mut definition = definition();
    let before = definition.profiles[&ProfileName::from("research")].clone();
    selected.compose_definition(&mut definition).unwrap();
    assert_eq!(definition.profiles[&ProfileName::from("research")], before);
    assert_eq!(definition.profiles.len(), 2);
    let profile = definition.profiles[selected.profile_name()]
        .as_inline()
        .unwrap();
    let mut expected = before.as_inline().unwrap().clone();
    expected.tools.mcp_servers.push(selected.server().clone());
    expected
        .tools
        .rust_bundles
        .push(meerkat_toolkit::setup::SETUP_RESULTS_BUNDLE.into());
    assert_eq!(profile, &expected);
    assert!(profile.tools.shell);
    assert_eq!(profile.tools.mcp, ["browser"]);
    assert_eq!(
        profile.tools.rust_bundles,
        [
            "trusted-research",
            meerkat_toolkit::setup::SETUP_RESULTS_BUNDLE
        ]
    );
    assert!(
        !profile
            .tools
            .rust_bundles
            .iter()
            .any(|bundle| bundle == toolkit_mobkit::FIND_AND_INSTALL_BUNDLE)
    );
    let access = selected.server().access.as_ref().unwrap();
    let expected_operations = PREPARATION_TOOLS
        .iter()
        .chain(ACQUISITION_TOOLS)
        .map(|name| (*name).to_string())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(access.allowed_operations, expected_operations);
    assert!(access.permits("setup_acquire_python"));
    assert!(access.permits("setup_search_node"));
    assert!(access.permits("setup_acquire_node"));
    let preparation = helper(SetupHelperTools::Preparation);
    let preparation_access = preparation.server().access.as_ref().unwrap();
    assert!(!preparation_access.permits("setup_search_node"));
    assert!(!preparation_access.permits("setup_acquire_node"));
    assert!(!access.permits("setup_install"));
    assert!(!access.permits("unadvertised_operation"));
    // This checks the public durable Profile shape only. It deliberately does
    // not claim native PortableProfile sealing, which requires native support.
    let restored: MobDefinition =
        serde_json::from_slice(&serde_json::to_vec(&definition).unwrap()).unwrap();
    assert_eq!(restored, definition);
    assert_eq!(selected.member().mob_id, selected.source_member().mob_id);
    assert_eq!(selected.member().member, selected.source_member().member);
    assert_ne!(selected.member().role, selected.source_member().role);
    assert_eq!(selected.member().role, selected.profile_name().as_str());
}

#[test]
fn exact_restart_reuses_profile_and_conflict_refuses_without_mutation() {
    for tools in [SetupHelperTools::Preparation, SetupHelperTools::CheckedInstallation] {
        let selected = helper(tools);
        let same = helper(tools);
        assert_eq!(selected.member(), same.member());
        let mut definition = definition();
        selected.compose_definition(&mut definition).unwrap();
        let retained = definition.clone();
        same.compose_definition(&mut definition).unwrap();
        assert_eq!(definition, retained);
        if tools == SetupHelperTools::Preparation {
            assert!(!selected.server().access.as_ref().unwrap().permits("setup_acquire_python"));
        }

        // A different selected operation ceiling cannot silently replace the
        // already prepared profile, even when its transport/config is identical.
        assert!(
            helper(SetupHelperTools::InertAcquisition)
                .compose_definition(&mut definition)
                .is_err()
        );
        assert_eq!(definition, retained);
        definition
            .profiles
            .get_mut(selected.profile_name())
            .unwrap()
            .as_inline_mut()
            .unwrap()
            .tools
            .mcp_servers
            .last_mut()
            .unwrap()
            .access = None;
        let conflict = definition.clone();
        assert!(selected.compose_definition(&mut definition).is_err());
        assert_eq!(definition, conflict);
    }
}

#[test]
fn selected_member_guard_preserves_other_users_of_the_source_profile() {
    for tools in [SetupHelperTools::Preparation, SetupHelperTools::CheckedInstallation] {
        let selected = helper(tools);
        let guard = SelectedHelperCustomizer(selected.clone());
        let mob = MobId::from("household");
        let source_role = ProfileName::from("research");
        let research = definition().profiles[&source_role]
            .as_inline()
            .unwrap()
            .clone();
        let mut ordinary = SpawnMemberSpec::new(source_role.clone(), "ordinary-agent");
        ordinary.override_profile = Some(research.clone());
        ordinary.tool_access_policy = Some(ToolAccessPolicy::ReadOnly);
        guard.apply(&mob, &source_role, &mut ordinary).unwrap();
        assert_eq!(ordinary.override_profile, Some(research));
        assert_eq!(
            ordinary.tool_access_policy,
            Some(ToolAccessPolicy::ReadOnly)
        );
        assert_eq!(ordinary.role_name, source_role);

        let mut foreign = SpawnMemberSpec::new(selected.profile_name().clone(), "ordinary-agent");
        assert!(
            guard
                .apply(&mob, selected.profile_name(), &mut foreign)
                .is_err()
        );
        let mut selected_wrong_role =
            SpawnMemberSpec::new("research", selected.member().member.as_str());
        assert!(
            guard
                .apply(&mob, &source_role, &mut selected_wrong_role)
                .is_err()
        );
        let mut matching = SpawnMemberSpec::new(
            selected.profile_name().clone(),
            selected.member().member.as_str(),
        );
        guard
            .apply(&mob, selected.profile_name(), &mut matching)
            .unwrap();
        assert!(matching.override_profile.is_none());
        assert!(
            guard
                .apply(
                    &MobId::from("foreign-mob"),
                    selected.profile_name(),
                    &mut matching
                )
                .is_err()
        );
        assert!(guard.apply(&mob, &source_role, &mut matching).is_err());
    }
}

#[test]
fn earlier_native_profile_overlay_and_global_policy_survive_selected_composition() {
    let selected = helper(SetupHelperTools::InertAcquisition);
    let guard = SelectedHelperCustomizer(selected.clone());
    let mut prior = definition().profiles[&ProfileName::from("research")]
        .as_inline()
        .unwrap()
        .clone();
    prior.peer_description = "Prior host customizer overlay".into();
    let mut expected = prior.clone();
    expected.tools.mcp_servers.push(selected.server().clone());
    expected
        .tools
        .rust_bundles
        .push(meerkat_toolkit::setup::SETUP_RESULTS_BUNDLE.into());
    let mut spec = SpawnMemberSpec::new(
        selected.profile_name().clone(),
        selected.member().member.as_str(),
    );
    spec.override_profile = Some(prior);
    spec.tool_access_policy = Some(ToolAccessPolicy::ReadOnly);
    let mob = MobId::from("household");
    guard
        .apply(&mob, selected.profile_name(), &mut spec)
        .unwrap();
    guard
        .apply(&mob, selected.profile_name(), &mut spec)
        .unwrap();
    assert_eq!(spec.override_profile, Some(expected));
    assert_eq!(spec.tool_access_policy, Some(ToolAccessPolicy::ReadOnly));
    spec.override_profile
        .as_mut()
        .unwrap()
        .tools
        .mcp_servers
        .last_mut()
        .unwrap()
        .access = None;
    let before = spec.override_profile.clone();
    assert!(
        guard
            .apply(&mob, selected.profile_name(), &mut spec)
            .is_err()
    );
    assert_eq!(spec.override_profile, before);
}

#[test]
fn wrong_mob_unresolved_profile_and_existing_setup_provider_refuse() {
    let selected = helper(SetupHelperTools::Preparation);
    let mut original = definition();
    original.id = MobId::from("foreign-mob");
    let before = original.clone();
    assert!(selected.compose_definition(&mut original).is_err());
    assert_eq!(original, before);
    let mut unresolved = definition();
    unresolved.profiles.insert(
        ProfileName::from("research"),
        ProfileBinding::RealmRef {
            realm_profile: "realm-research".into(),
        },
    );
    let before = unresolved.clone();
    assert!(selected.compose_definition(&mut unresolved).is_err());
    assert_eq!(unresolved, before);
    for direct in [false, true] {
        let mut conflict = definition();
        let source = conflict
            .profiles
            .get_mut(&ProfileName::from("research"))
            .unwrap()
            .as_inline_mut()
            .unwrap();
        if direct {
            source.tools.mcp_servers.push(selected.server().clone());
        } else {
            source.tools.mcp.push(SERVER_NAME.into());
        }
        let before = conflict.clone();
        assert!(selected.compose_definition(&mut conflict).is_err());
        assert_eq!(conflict, before);
    }
}

#[test]
fn exclusive_role_composition_preserves_role_keys_and_refuses_server_substitution() {
    let selected = PreparedSetupConnection::from_preparer_output(
        br#"{"mcpServers":{"toolkit-setup":{"command":"/usr/bin/python3","args":["-I","-B","/retained/setup-adapter.py"]}}}"#,
    ).unwrap().for_mobkit_helper_in_place(source_member(), SetupHelperTools::InertAcquisition).unwrap();
    assert_eq!(selected.member(), &source_member());
    let mut actual = definition();
    let mut expected = actual.clone();
    expected
        .profiles
        .get_mut(&ProfileName::from("research"))
        .unwrap()
        .as_inline_mut()
        .unwrap()
        .tools
        .mcp_servers
        .push(selected.server().clone());
    expected
        .profiles
        .get_mut(&ProfileName::from("research"))
        .unwrap()
        .as_inline_mut()
        .unwrap()
        .tools
        .rust_bundles
        .push(meerkat_toolkit::setup::SETUP_RESULTS_BUNDLE.into());
    selected.compose_definition(&mut actual).unwrap();
    assert_eq!(actual, expected);
    selected.compose_definition(&mut actual).unwrap();
    assert_eq!(actual, expected);
    assert!(
        selected
            .server()
            .access
            .as_ref()
            .unwrap()
            .permits("setup_acquire_python")
    );
    assert!(
        !selected
            .server()
            .access
            .as_ref()
            .unwrap()
            .permits("setup_install")
    );
    let guard = SelectedHelperCustomizer(selected.clone());
    let mob = MobId::from("household");
    let role = ProfileName::from("research");
    let mut matching = SpawnMemberSpec::new(role.clone(), "setup-helper");
    matching.tool_access_policy = Some(ToolAccessPolicy::ReadOnly);
    guard.apply(&mob, &role, &mut matching).unwrap();
    assert_eq!(
        matching.tool_access_policy,
        Some(ToolAccessPolicy::ReadOnly)
    );
    let mut foreign = SpawnMemberSpec::new(role.clone(), "other-identity");
    assert!(guard.apply(&mob, &role, &mut foreign).is_err());
    for duplicate in [false, true] {
        let mut conflict = actual.clone();
        let servers = &mut conflict
            .profiles
            .get_mut(&role)
            .unwrap()
            .as_inline_mut()
            .unwrap()
            .tools
            .mcp_servers;
        if duplicate {
            servers.push(selected.server().clone());
        } else {
            servers.last_mut().unwrap().access = None;
        }
        let before = conflict.clone();
        assert!(selected.compose_definition(&mut conflict).is_err());
        assert_eq!(conflict, before);
    }
}
