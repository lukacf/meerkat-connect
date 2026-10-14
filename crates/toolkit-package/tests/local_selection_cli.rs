#![cfg(feature = "local-recipes")]

use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use toolkit_package::{ContentDigest, IntegrationPackage, LocalSelectionProfile};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::write(
            root.join("package.json"),
            include_bytes!("fixtures/python-install/package.json"),
        )
        .unwrap();
        fs::write(
            root.join("selection.json"),
            include_bytes!("fixtures/python-install/activation.json"),
        )
        .unwrap();
        fs::write(
            root.join("verification.json"),
            serde_json::to_vec(&json!([
                {"owner": "fixture-observations", "record": "historical-install", "revision": "1"}
            ]))
            .unwrap(),
        )
        .unwrap();
        Self { _temp: temp, root }
    }

    fn args(&self, verb: &str) -> Vec<String> {
        vec![
            verb.into(),
            "--database".into(),
            self.root.join("recipes.sqlite").display().to_string(),
            "--realm".into(),
            "household".into(),
            "--owner".into(),
            "alice".into(),
        ]
    }

    fn save(&self) -> Vec<String> {
        let mut args = self.args("save");
        for (flag, file) in [
            ("--package", "package.json"),
            ("--selection", "selection.json"),
            ("--verification", "verification.json"),
        ] {
            args.extend([flag.into(), self.root.join(file).display().to_string()]);
        }
        args.extend(
            [
                "--profile",
                "python",
                "--component",
                "python-server",
                "--decision-owner",
                "fixture-decisions",
                "--decision-record",
                "selected-python",
                "--decision-revision",
                "1",
            ]
            .map(str::to_owned),
        );
        args
    }

    fn read(&self, digest: &str) -> Vec<String> {
        let mut args = self.args("read");
        args.extend(
            [
                "--publisher",
                "fixture",
                "--name",
                "python-server",
                "--version",
                "0.0.0-fixture",
                "--digest",
                digest,
            ]
            .map(str::to_owned),
        );
        args
    }
}

fn invoke(args: &[String], error: Option<&str>) -> Value {
    let result = Command::new(env!("CARGO_BIN_EXE_toolkit-local-recipes"))
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert_eq!(
        result.status.success(),
        error.is_none(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert!(
        result.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["scope"], "retained_recipe_metadata");
    if let Some(error) = error {
        assert_eq!(value["error"], error);
    }
    value
}

fn replace(args: &mut [String], flag: &str, value: &str) {
    let index = args.iter().position(|s| s == flag).unwrap();
    args[index + 1] = value.into();
}

#[test]
fn exact_local_choice_reopens_without_claiming_current_authority() {
    let fixture = Fixture::new();
    let saved = invoke(&fixture.save(), None);
    assert_eq!(saved["status"], "retained");
    let summary = &saved["recipe"];
    assert_eq!(summary["kind"], "local_selection");
    assert_eq!(summary["profile"], "python");
    assert_eq!(
        summary["reuse"],
        "requires_current_host_selection_and_artifact_validation"
    );
    assert_eq!(summary["verification"][0]["record"], "historical-install");
    assert_eq!(invoke(&fixture.save(), None), saved);
    let digest = summary["digest"].as_str().unwrap();
    let read = invoke(&fixture.read(digest), None);
    assert_eq!(read["status"], "found");
    for (key, file) in [
        ("package_json", "package.json"),
        ("selection_json", "selection.json"),
    ] {
        assert_eq!(
            read["recipe"]["documents"][key],
            fs::read_to_string(fixture.root.join(file)).unwrap()
        );
    }
    assert_eq!(
        invoke(&fixture.args("list"), None)["recipes"],
        json!([summary])
    );
    invoke(
        &fixture.read(&"0".repeat(64)),
        Some("stored_recipe_unverified"),
    );
    for (flag, scope) in [("--owner", "bob"), ("--realm", "other")] {
        let mut args = fixture.read(digest);
        replace(&mut args, flag, scope);
        assert_eq!(invoke(&args, None)["status"], "not_found");
    }
}

#[test]
fn changed_document_formatting_and_evidence_cannot_replace_an_identity() {
    let fixture = Fixture::new();
    let saved = invoke(&fixture.save(), None);
    let bytes = fs::read(fixture.root.join("selection.json")).unwrap();
    let mut changed = bytes.clone();
    changed.push(b'\n');
    fs::write(fixture.root.join("selection.json"), changed).unwrap();
    invoke(&fixture.save(), Some("immutable_conflict"));
    fs::write(fixture.root.join("selection.json"), bytes).unwrap();
    let mut args = fixture.save();
    replace(&mut args, "--decision-revision", "2");
    invoke(&args, Some("immutable_conflict"));
    fs::write(
        fixture.root.join("verification.json"),
        br#"[{"owner":"fixture-observations","record":"historical-install","revision":"2"}]"#,
    )
    .unwrap();
    invoke(&fixture.save(), Some("immutable_conflict"));
    let read = invoke(
        &fixture.read(saved["recipe"]["digest"].as_str().unwrap()),
        None,
    );
    assert_eq!(read["recipe"]["verification"][0]["revision"], "1");
}

#[test]
fn invalid_or_mixed_inputs_are_refused_before_database_creation() {
    let fixture = Fixture::new();
    for profile in ["ruby", "Python", "remote"] {
        let mut args = fixture.save();
        replace(&mut args, "--profile", profile);
        invoke(&args, Some("unsupported_local_profile"));
    }
    let mut args = fixture.save();
    replace(&mut args, "--profile", "node");
    invoke(&args, Some("invalid_local_selection"));
    let mut args = fixture.save();
    replace(&mut args, "--component", "other");
    invoke(&args, Some("invalid_local_selection"));
    let mut args = fixture.save();
    args.extend([
        "--plugin".into(),
        fixture.root.join("package.json").display().to_string(),
    ]);
    invoke(&args, Some("invalid_arguments"));
    fs::write(fixture.root.join("verification.json"), b"[]").unwrap();
    invoke(&fixture.save(), Some("invalid_local_selection"));
    assert!(!fixture.root.join("recipes.sqlite").exists());
}

fn mcpb_fixture() -> Fixture {
    let fixture = Fixture::new();
    fs::write(
        fixture.root.join("package.json"),
        include_bytes!("fixtures/node-install/package.json"),
    )
    .unwrap();
    let mut selection: Value =
        serde_json::from_slice(include_bytes!("fixtures/node-install/activation.json")).unwrap();
    let configuration = b"{\n  \"toolsets\": \"geometry\"\n}\n";
    selection["configuration"]["content_digest"] = json!(ContentDigest::of_bytes(configuration));
    selection["components"][0]["source"]["dependencies"] = json!({"kind":"self_contained"});
    fs::write(
        fixture.root.join("selection.json"),
        serde_json::to_vec(&selection).unwrap(),
    )
    .unwrap();
    fs::write(fixture.root.join("configuration.json"), configuration).unwrap();
    fixture
}

fn mcpb_save(fixture: &Fixture) -> Vec<String> {
    let mut args = fixture.save();
    replace(&mut args, "--profile", "mcpb");
    replace(&mut args, "--component", "node-server");
    args.extend([
        "--configuration".into(),
        fixture
            .root
            .join("configuration.json")
            .display()
            .to_string(),
    ]);
    args
}

#[test]
fn mcpb_roundtrip_preserves_exact_configuration_in_the_same_store() {
    let fixture = mcpb_fixture();
    let saved = invoke(&mcpb_save(&fixture), None);
    assert_eq!(saved["recipe"]["profile"], "mcpb");
    let mut args = fixture.read(saved["recipe"]["digest"].as_str().unwrap());
    replace(&mut args, "--name", "node-server");
    let found = invoke(&args, None);
    assert_eq!(
        found["recipe"]["documents"]["configuration_json"],
        fs::read_to_string(fixture.root.join("configuration.json")).unwrap()
    );
    assert_eq!(
        found["recipe"]["configuration_digest"],
        json!(ContentDigest::of_bytes(
            &fs::read(fixture.root.join("configuration.json")).unwrap()
        ))
    );
    assert_eq!(invoke(&mcpb_save(&fixture), None), saved);
    assert_eq!(
        invoke(&fixture.args("list"), None)["recipes"],
        json!([saved["recipe"].clone()])
    );
}

#[test]
fn mcpb_configuration_is_required_bound_and_exclusive_before_opening_store() {
    let fixture = mcpb_fixture();
    let mut args = mcpb_save(&fixture);
    args.truncate(args.len() - 2);
    invoke(&args, Some("invalid_arguments"));
    // The Python selection would already fail, so use a valid Python fixture
    // to prove that this extra flag cannot be silently ignored.
    let python = Fixture::new();
    let mut python_args = python.save();
    python_args.extend([
        "--configuration".into(),
        fixture
            .root
            .join("configuration.json")
            .display()
            .to_string(),
    ]);
    invoke(&python_args, Some("invalid_arguments"));
    assert!(!python.root.join("recipes.sqlite").exists());
    fs::write(
        fixture.root.join("configuration.json"),
        b"{\"toolsets\":\"changed\"}",
    )
    .unwrap();
    invoke(&mcpb_save(&fixture), Some("invalid_local_selection"));
    // Bind duplicate-key bytes to isolate syntax refusal from digest refusal.
    let duplicate = b"{\"toolsets\":\"one\",\"toolsets\":\"two\"}";
    fs::write(fixture.root.join("configuration.json"), duplicate).unwrap();
    let mut selection: Value =
        serde_json::from_slice(&fs::read(fixture.root.join("selection.json")).unwrap()).unwrap();
    selection["configuration"]["content_digest"] = json!(ContentDigest::of_bytes(duplicate));
    fs::write(
        fixture.root.join("selection.json"),
        serde_json::to_vec(&selection).unwrap(),
    )
    .unwrap();
    invoke(&mcpb_save(&fixture), Some("invalid_local_selection"));
    assert!(!fixture.root.join("recipes.sqlite").exists());
}

#[test]
fn local_metadata_does_not_become_a_remote_export() {
    let fixture = Fixture::new();
    let saved = invoke(&fixture.save(), None);
    let mut args = fixture.read(saved["recipe"]["digest"].as_str().unwrap());
    args[0] = "export".into();
    args.extend([
        "--selection".into(),
        fixture.root.join("selection.json").display().to_string(),
        "--destination".into(),
        fixture.root.join("must-not-exist").display().to_string(),
    ]);
    invoke(&args, Some("stored_recipe_unverified"));
    assert!(!fixture.root.join("must-not-exist").exists());
}

const PYTHON_PACKAGE: &[u8] = include_bytes!("fixtures/python-install/package.json");
const NODE_PACKAGE: &[u8] = include_bytes!("fixtures/node-install/package.json");

// Explicit software declaration fixture, independent of ActivationManifest.
fn software_documents(profile: LocalSelectionProfile) -> (&'static [u8], Vec<u8>, &'static str) {
    let (bytes, runtime, component, strategy, location, executable, artifacts) = match profile {
        LocalSelectionProfile::Python => (PYTHON_PACKAGE, "python", "python-server", "python-local",
            "https://example.invalid/fixture_server-1.0-py3-none-any.whl", "fixture_server/__main__.py",
            json!({"requirements":"2".repeat(64),"dependency_one-1.0-py3-none-any.whl":"3".repeat(64)})),
        LocalSelectionProfile::Node => (NODE_PACKAGE, "node", "node-server", "node-local",
            "https://example.invalid/node-server.tgz", "dist/index.js",
            json!({"package-json":"2".repeat(64),"package-lock":"3".repeat(64),"dependency-archive":"4".repeat(64)})),
        LocalSelectionProfile::Mcpb => panic!("full MCPB path only"),
    };
    let package: IntegrationPackage = serde_json::from_slice(bytes).unwrap();
    let value = json!({"schema_version":1,"document_kind":"local_software_declaration",
        "package":package.identity,"package_content_digest":package.content_digest().unwrap(),"strategy":strategy,
        "components":[{"id":component,"version":"0.0.0-fixture","runtime":runtime,
            "source":{"kind":"artifact","location":location,"content_digest":"1".repeat(64),
                "dependencies":{"kind":"pinned_closure","artifacts":artifacts},
                "entrypoint":{"executable":executable,"arguments":[]}}}],
        "exports":[{"role":"service_connector","id":"service","components":[component],
            "authentication":{"kind":"none"},"operations":[{"id":"fixture-read","schema_digest":"5".repeat(64),
                "declared_effect":"read","required_authority":["read"],"resources":{"kind":"connection_wide"},
                "result_limits":{"maximum_bytes":4096,"maximum_items":10}}]}],
        "portable_mcp_entries":[{"name":"software-server","component":component,
            "operation_tools":{"fixture-read":"actual_read"}}]});
    (bytes, serde_json::to_vec_pretty(&value).unwrap(), component)
}

#[test]
fn software_save_cli_retains_exact_new_form_for_python_and_node_and_refuses_cross_form_flags() {
    for profile in [LocalSelectionProfile::Python,LocalSelectionProfile::Node] {
        let fixture=Fixture::new();
        let (package,declaration,component)=software_documents(profile);
        fs::write(fixture.root.join("package.json"),package).unwrap();
        fs::write(fixture.root.join("declaration.json"),&declaration).unwrap();
        let mut args=fixture.save();
        let selection=args.iter().position(|a| a=="--selection").unwrap();
        args[selection]="--declaration".into();
        args[selection+1]=fixture.root.join("declaration.json").display().to_string();
        replace(&mut args,"--profile",if profile==LocalSelectionProfile::Python {"python"} else {"node"});
        replace(&mut args,"--component",component);
        let mut both=args.clone(); both.extend(["--selection".into(),fixture.root.join("selection.json").display().to_string()]);
        invoke(&both,Some("invalid_arguments"));
        let mut wrong=args.clone();wrong[selection]="--selection".into();
        invoke(&wrong,Some("invalid_local_selection"));
        assert!(!fixture.root.join("recipes.sqlite").exists());
        let saved=invoke(&args,None);
        assert_eq!(saved["recipe"]["kind"],"local_software_selection");
        assert_eq!(saved["recipe"]["document_kind"],"local_software_declaration");
        assert!(saved["recipe"].get("manifest_digest").is_none());
        assert!(saved["recipe"].get("configuration_digest").is_none());
        assert_eq!(invoke(&args,None),saved);
        let mut read=fixture.read(saved["recipe"]["digest"].as_str().unwrap());
        replace(&mut read,"--name",component);
        let reopened=invoke(&read,None);
        assert_eq!(reopened["recipe"]["documents"]["declaration_json"],String::from_utf8(declaration).unwrap());
        assert_eq!(reopened["recipe"]["documents"]["package_json"],std::str::from_utf8(package).unwrap());
        assert!(reopened["recipe"]["documents"].get("selection_json").is_none());
        assert_eq!(invoke(&fixture.args("list"),None)["recipes"],json!([saved["recipe"].clone()]));
    }
}
