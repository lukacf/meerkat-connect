//! Closed request and actual checked-selection controls. Package responses are
//! synthetic; these controls do not execute native persistence or a provider.
use super::*;

#[test]
fn credential_request_refuses_values_authority_and_mixed_oauth_without_changing_legacy_parser() {
    let base = json!({"job_id":"checked-job","authentication":{"kind":"declared_secret_slots"},
        "operations":["read"],"agent":"original-agent","expires_in_ms":null});
    assert!(parse(&base.to_string()).is_ok());
    for (field, value) in [("credentials",json!({"KEY":"must-not-enter-the-model"})),
        ("realm",json!("other")),("configuration",json!({})),("slot",json!("KEY")),
        ("connector",json!({})),("grant",json!({})),("operations",json!(["read","read"]))] {
        let mut altered = base.clone(); altered[field] = value;
        assert!(parse(&altered.to_string()).is_err(), "{field}");
    }
    let mut missing = base.clone(); missing.as_object_mut().unwrap().remove("expires_in_ms");
    assert!(parse(&missing.to_string()).is_err());
    assert!(parse(&format!("{{\"job_id\":\"second\",{}", &base.to_string()[1..])).is_err());
    let oauth = json!({"job_id":"checked-job","agent":"original-agent","expires_in_ms":null,
        "connector":{"slot_id":"selected-slot","issuer":"https://issuer.test","client":"client",
            "resource":"https://api.test","scopes":["read"],"strategy_id":"oidc-userinfo-v1",
            "account_selection":null},
        "operations":{"read":{"required_scopes":["read"],"destination_origin":"https://api.test"}}});
    assert!(!is_proposal(&oauth.to_string()).unwrap());
    assert!(super::super::parse(&oauth.to_string()).is_ok());
    assert!(super::super::parse(&base.to_string()).is_err());
}

#[tokio::test]
async fn credential_review_uses_exact_checked_slots_and_launch_and_refuses_retired_or_widened_selection() {
    let root = tempfile::tempdir().unwrap();
    let fixture = crate::stdio::tests::selected_public_fixture(root.path(), Some(json!({
        "authentication":{"kind":"binding","owner":"process","requirement":"key","credential_audience":"service"},
        "operation_tools":{"declared/read":"actual_read"},
        "environment_secret_slots":["FIXTURE_KEY","FIXTURE_TOKEN"]}))).await;
    let selected = fixture.raw_selection().ok().unwrap();
    let selection = CredentialSelection { operations:["actual_read".to_owned()].into(),
        agent:"original-agent".into(),expires_in_ms:None,tool_policy:None };
    let (config, slots) = checked_configuration(&selected, &selection).unwrap();
    assert_eq!(slots.iter().map(|slot| slot.environment_variable().to_owned()).collect::<BTreeSet<_>>(),
        ["FIXTURE_KEY".to_owned(),"FIXTURE_TOKEN".to_owned()].into());
    let request = credential_review_request(&selected, &config, &selection).unwrap();
    let body = request.request_body.as_ref().unwrap();
    assert_eq!(body["installation"], serde_json::to_value(&config).unwrap());
    assert_eq!(body["phase"], "installed_credential_service_access");
    assert_eq!(body["authentication"], json!({"kind":"declared_secret_slots"}));
    assert_eq!(body["application_selection"]["operations"], json!(["actual_read"]));
    assert!(body["notice"].as_str().unwrap().contains("Saved configuration or credentials can remain"));
    assert!(!body["notice"].as_str().unwrap().contains("Realm configuration is not changed"));
    assert!(selected.public_configuration(&selection.operations).is_err());
    let mut changed = config.clone();
    changed.access = Some(meerkat_core::McpServerAccess::allowing(["other_write".to_owned()]));
    assert!(credential_review_request(&selected, &changed, &selection).is_err());
    let widened = CredentialSelection { operations:["actual_read".to_owned(),"other_write".to_owned()].into(),
        agent:selection.agent.clone(),expires_in_ms:None,tool_policy:None };
    assert!(checked_configuration(&selected, &widened).is_err());
    fixture.owner.retire();
    assert!(credential_review_request(&selected, &config, &selection).is_err());
}

// The package response remains synthetic, but the checked selection, review
// producer, ApprovalService decision, parser and launch derivation are real.
#[cfg(all(unix, feature = "console"))]
#[tokio::test]
async fn credential_review_round_trips_the_installation_reader_without_losing_checked_evidence() {
    use crate::resources::installation_readback::checked_credential_review_for_test as read;
    use meerkat_core::ApprovalService;
    let root = tempfile::tempdir().unwrap();
    let declaration = json!({
        "authentication":{"kind":"binding","owner":"process","requirement":"key","credential_audience":"service"},
        "operation_tools":{"declared/read":"actual_read"},
        "environment_secret_slots":["FIXTURE_KEY","FIXTURE_TOKEN"]});
    let fixture = crate::stdio::tests::selected_public_fixture(root.path(), Some(declaration.clone())).await;
    let selected = fixture.raw_selection().ok().unwrap();
    let selection = CredentialSelection { operations:["actual_read".to_owned()].into(),
        agent:"original-agent".into(),expires_in_ms:None,tool_policy:None };
    let (config, slots) = checked_configuration(&selected, &selection).unwrap();
    let request = credential_review_request(&selected, &config, &selection).unwrap();
    let approvals = ApprovalService::new();
    let pending = approvals.request(request).unwrap();
    let approved = approvals.decide(&pending.approval_id, ApprovalDecision::Approve,
        ApprovalPrincipalId::new("credential-reader-control").unwrap(), None, None).unwrap();
    let software = &selected.installed;
    let basis = selected.operation_basis();
    let mut result = json!({"scope":"retained_payload_and_launch_binding_only",
        "selection_kind":software.profile,"mcp_path":software.mcp_path,"receipt_path":software.receipt_path,
        "receipt_sha256":software.receipt_sha256,"configuration_sha256":software.configuration_sha256,
        "mcp_configuration":*selected.configuration,"declared_service":declaration,
        "package_sha256":basis["package_sha256"],"effect_sha256":basis["effect_sha256"],
        "plugin_source":basis["source"]["plugin_source"],"acquired_source":basis["source"]["acquired_source"]});
    for key in ["selection_sha256", "manifest_digest", "document_kind", "declaration_digest"] {
        if let Some(value) = basis.get(key) { result[key] = value.clone(); }
    }
    let (observed, recovery) = read(&approved, &software.realm, &result).unwrap();
    assert_eq!(observed, config);
    assert!(recovery.get("public_service").is_none());
    assert_eq!(recovery["credential_service"]["credential_slots"], serde_json::to_value(&slots).unwrap());
    assert_eq!(recovery["software"]["mcp_path"], json!(software.mcp_path));
    assert_eq!(recovery["software"]["receipt_path"], json!(software.receipt_path));
    assert_eq!(recovery["software"]["document_sha256"], software.mcp_document_sha256);
    assert_eq!(recovery["software"]["recovery_request_sha256"], json!(software.recovery_request_sha256));
    for field in ["mcp_path", "receipt_path", "document_sha256", "recovery_request_sha256"] {
        let mut missing = approved.clone();
        missing.request_body.as_mut().unwrap()["software"].as_object_mut().unwrap().remove(field);
        assert!(read(&missing, &software.realm, &result).is_err(), "missing artifact evidence");
    }
    for field in ["receipt_sha256", "effect_sha256", "package_sha256", "mcp_path"] {
        let mut changed = result.clone(); changed[field] = json!("changed");
        assert!(read(&approved, &software.realm, &changed).is_err(), "changed artifact evidence");
    }
    for mode in ["missing", "extra", "wrong-source", "unknown-field", "duplicate", "declared-removed", "declared-auth", "operation", "reviewed-slot", "reviewed-command", "inline-env", "native-secret-env"] {
        let mut record = approved.clone(); let mut value = result.clone();
        let body = record.request_body.as_mut().unwrap();
        match mode {
            "missing" => { body.as_object_mut().unwrap().remove("credential_slots"); },
            "extra" => { body["credential_slots"].as_array_mut().unwrap().push(json!({"source":"selected_environment","declaration":"EXTRA"})); },
            "wrong-source" => body["credential_slots"][0] = json!({"source":"library_field","declaration":{"field_path":["config","key"],"environment_variable":"FIXTURE_KEY"}}),
            "unknown-field" => body["credential_slots"][0]["secret"] = json!("not-an-input"),
            "duplicate" => { let first = body["credential_slots"][0].clone(); body["credential_slots"][1] = first; },
            "declared-removed" => value["declared_service"]["environment_secret_slots"] = json!(["FIXTURE_KEY"]),
            "declared-auth" => value["declared_service"]["authentication"] = json!({"kind":"none"}),
            "operation" => body["application_selection"]["operations"] = json!(["other_write"]),
            "reviewed-slot" => body["installation"]["secret_env"] = json!(["FIXTURE_KEY"]),
            "reviewed-command" => body["installation"]["command"] = json!("/different/command"),
            "inline-env" => value["mcp_configuration"]["mcpServers"][software.server_name.as_str()]["env"] = json!({"PRIVATE":"must-not-load"}),
            "native-secret-env" => value["mcp_configuration"]["mcpServers"][software.server_name.as_str()]["secret_env"] = json!(["FIXTURE_KEY"]),
            _ => unreachable!(),
        }
        if matches!(mode, "inline-env" | "native-secret-env") {
            use sha2::{Digest, Sha256};
            body["software"]["document_sha256"] = json!(format!("{:x}", Sha256::digest(
                serde_json::to_vec(&value["mcp_configuration"]).unwrap())));
        }
        assert!(read(&record, &software.realm, &value).is_err(), "{mode}");
    }
    let mut legacy = approved.clone();
    legacy.request_body.as_mut().unwrap()["phase"] = json!("installed_account_access");
    assert!(read(&legacy, &software.realm, &result).is_err());
}
