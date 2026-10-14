//! Controlled issuer -> configured Meta verifier -> normal POST /console/send
//! -> CurrentHumanBinder -> actual InstalledConsoleIngress. Fixture login and
//! signing prove this composed route, not deployed application authentication.
use super::*;
use axum::http::{header, HeaderMap, Uri};
use meerkat_core::{auth::principal::TrustDomainId, PrincipalKind};
use meerkat_mobkit::access::{AccessControlConfig, AccessRule};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{oneshot, Semaphore};

const ISSUER: &str = "https://controlled-console.invalid";
const SUBJECT: &str = "controlled-subject";
const EMAIL: &str = "different-display@example.invalid";
const SCOPE: &str = "controlled-login-a";
const AUDIENCE: &str = "controlled-console";
// Public fixture material only. No deployed signing key or user credential.
const KEY: &[u8] = b"controlled-console-fixture-key-only";

#[derive(Clone, Copy)]
enum Case { Valid, Retired, RetiredAfterSelection, MismatchedScope, TamperedSignature, WrongIssuer }

fn selected_human() -> PrincipalRef {
    PrincipalRef::in_domain(PrincipalKind::Human, SUBJECT,
        TrustDomainId::new(format!("oidc-issuer:{ISSUER}")).unwrap()).unwrap()
}

// Minimal fixture encoding uses the target's existing sha2 dependency. Native
// verification is always performed by Meta; this is not a second verifier.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        result.push(ALPHABET[(chunk[0] >> 2) as usize] as char);
        result.push(ALPHABET[(((chunk[0] & 3) << 4) | chunk.get(1).copied().unwrap_or(0) >> 4) as usize] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[(((chunk[1] & 15) << 2) | chunk.get(2).copied().unwrap_or(0) >> 6) as usize] as char);
        }
        if chunk.len() > 2 { result.push(ALPHABET[(chunk[2] & 63) as usize] as char); }
    }
    result
}
fn signed_fixture(issuer: &str, scope: &str, expires: u64) -> String {
    let header = base64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = base64url(&serde_json::to_vec(&serde_json::json!({
        "iss": issuer, "aud": AUDIENCE, "sub": SUBJECT, "email": EMAIL,
        "email_verified": true, "sid": scope, "exp": expires,
    })).unwrap());
    let unsigned = format!("{header}.{claims}");
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    assert!(KEY.len() <= inner_pad.len());
    for (index, byte) in KEY.iter().enumerate() {
        inner_pad[index] ^= *byte;
        outer_pad[index] ^= *byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(unsigned.as_bytes());
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    format!("Bearer {unsigned}.{}", base64url(&outer.finalize()))
}

struct RouteObservation {
    selected: AtomicUsize,
    attempted: AtomicUsize,
    human: Mutex<Option<AuthenticatedConsoleHuman>>,
    raw: Mutex<Option<Input>>,
    bound: Mutex<Option<Input>>,
    failure: Mutex<Option<String>>,
    pause: bool,
    entered: Semaphore,
    release: Semaphore,
    finished: Semaphore,
}
impl RouteObservation {
    fn new(pause: bool) -> Self {
        Self { selected: AtomicUsize::new(0), attempted: AtomicUsize::new(0),
            human: Mutex::new(None), raw: Mutex::new(None), bound: Mutex::new(None), failure: Mutex::new(None),
            pause, entered: Semaphore::new(0), release: Semaphore::new(0), finished: Semaphore::new(0) }
    }
}
struct ObserveInstalledIngress {
    inner: Arc<dyn ConsoleGovernedIngress>, observation: Arc<RouteObservation>,
}
impl ConsoleGovernedIngress for ObserveInstalledIngress {
    fn governs(&self, identity: &AgentIdentity) -> bool { self.inner.governs(identity) }
    fn binder_for(&self, identity: &AgentIdentity, human: &AuthenticatedConsoleHuman)
        -> Result<Arc<dyn GovernedInputBinder>, String>
    {
        self.observation.attempted.fetch_add(1, Ordering::SeqCst);
        *self.observation.human.lock().unwrap() = Some(human.clone());
        let inner = self.inner.binder_for(identity, human)?;
        self.observation.selected.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(ObserveInstalledBinder { inner, observation: self.observation.clone() }))
    }
}
struct ObserveInstalledBinder {
    inner: Arc<dyn GovernedInputBinder>, observation: Arc<RouteObservation>,
}
#[async_trait::async_trait]
impl GovernedInputBinder for ObserveInstalledBinder {
    async fn bind(&self, context: &GovernedBindContext, input: Input) -> Result<BoundGovernedInput, String> {
        // The native HTTP handler has already captured its real verified Human
        // and selected the actual installed binder. Pause before that binder's
        // first operation so retirement must invalidate its retained login.
        if self.observation.pause {
            self.observation.entered.add_permits(1);
            let permit = self.observation.release.acquire().await.map_err(|_| "fixture gate closed")?;
            permit.forget();
        }
        *self.observation.raw.lock().unwrap() = Some(input.clone());
        let result = self.inner.bind(context, input).await;
        match &result {
            Ok(bound) => *self.observation.bound.lock().unwrap() = Some(bound.input.clone()),
            Err(error) => *self.observation.failure.lock().unwrap() = Some(error.clone()),
        }
        self.observation.finished.add_permits(1);
        result
    }
    fn retain_unresolved(&self, settlement: Box<dyn GovernedSettlement>, detail: &str) {
        self.inner.retain_unresolved(settlement, detail);
    }
}

// One bounded HTTP/1 request to the existing router. This is not a browser,
// replacement endpoint, token verifier, or general purpose HTTP client.
async fn post(address: std::net::SocketAddr, bearer: &str, member: &str) -> (u16, serde_json::Value) {
    tokio::time::timeout(WAIT, async {
        let body = serde_json::to_vec(&serde_json::json!({
            "identity": member, "content": "Answer this retained Console input",
            "origin": "console", "origin_kind": "operator", "idempotency_key": "controlled-verifier-input",
        })).unwrap();
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let request = format!("POST /console/send HTTP/1.1\r\nHost: {address}\r\nAuthorization: {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        let mut bytes = Vec::new();
        stream.take(1024 * 1024 + 1).read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.len() <= 1024 * 1024, "bounded fixture response");
        let split = bytes.windows(4).position(|part| part == b"\r\n\r\n").unwrap();
        let headers = std::str::from_utf8(&bytes[..split]).unwrap();
        let status = headers.lines().next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
        // Axum's finite Json responses have a content length. Refuse a different
        // response shape rather than silently parsing a partial/chunked body.
        let length: usize = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
        }).expect("normal finite Console JSON response");
        let body = &bytes[split + 4..];
        assert_eq!(body.len(), length);
        (status, serde_json::from_slice(body).unwrap())
    }).await.expect("bounded real Console request")
}

async fn controlled_console(case: Case) {
    let mut fixture = ContinuationFixture::for_console_input(selected_human()).await;
    let observation = Arc::new(RouteObservation::new(matches!(case, Case::RetiredAfterSelection)));
    let mut server = None;
    let result = AssertUnwindSafe(Box::pin(async {
        let native = fixture.lifetime().selected_policy().native_host.as_ref().unwrap();
        let member = native.members[0].member.member.clone();
        let route = fixture.source.route(&Id::new("console").unwrap()).unwrap();
        assert_eq!(route.requester, selected_human());
        assert_eq!(route.represented_subject.as_ref(), Some(&selected_human()));
        assert!(route.application_parent.is_none(), "Console input receives no service permission");
        let before_rows = fixture.store.list_records(&fixture.scope, None, 100).await.unwrap();
        let grant_path = fixture.source_path.with_file_name("grants.jsonl");
        let before_grants = std::fs::read(&grant_path).unwrap();
        assert_eq!(fixture.inputs().await, Ok(0));
        assert_eq!(fixture.model_requests(), 0);

        // The fixture authentication owner explicitly accepts one controlled
        // subject, then enrolls the exact lifetime before it mints any token.
        // ConsoleLogins itself is only the private transport lifetime owner.
        let (connection, logins) = ConsoleLogins::fixture_owner();
        let expires = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 600;
        let login = logins.fixture_enroll(1, crate::private_host::ConsoleLoginSelection {
            issuer: ISSUER.into(), subject: SUBJECT.into(), login_scope_id: SCOPE.into(), expires_at_ms: expires * 1000,
        }).unwrap();
        login.check().unwrap();
        let signed = signed_fixture(
            if matches!(case, Case::WrongIssuer) { "https://untrusted-console.invalid" } else { ISSUER },
            if matches!(case, Case::MismatchedScope) { "another-login" } else { SCOPE }, expires);
        let bearer = if matches!(case, Case::TamperedSignature) {
            let (prefix, signature) = signed.rsplit_once('.').unwrap();
            let first = if signature.as_bytes()[0] == b'A' { 'B' } else { 'A' };
            format!("{prefix}.{first}{}", &signature[1..])
        } else { signed };
        let decisions = meerkat_mobkit::console_auth_config::parse_console_auth_config(&serde_json::json!({
            "provider": "jwt", "shared_secret": std::str::from_utf8(KEY).unwrap(),
            "issuer": ISSUER, "audience": AUDIENCE, "email_allowlist": [EMAIL],
        })).unwrap();
        let access = AccessController::new(AccessControlConfig {
            enabled: true, admins: vec!["unrelated-fixture-admin".into()],
            rules: vec![AccessRule { id: "controlled-console-send".into(), subjects: vec![EMAIL.into()],
                actions: vec!["agent.view".into(), "agent.send".into()], agents: vec![member.clone()],
                ..Default::default() }], ..Default::default()
        }).unwrap();
        access.join_authorization_publication(fixture.source.authorization_publication()).unwrap();
        let ingress = fixture.source.console_ingress(logins.clone(), Some(access.clone())).await.unwrap();
        let runtime = fixture.native_for_console_mut();
        runtime.set_access_controller(access);
        runtime.set_console_governed_ingress(Arc::new(ObserveInstalledIngress { inner: ingress, observation: observation.clone() }));
        let resolver = runtime.console_viewer_resolver(&decisions);
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, bearer.parse().unwrap());
        let viewer = resolver.resolve(&headers, &Uri::from_static("/console/send"));
        let human = viewer.and_then(|viewer| viewer.human);
        let invalid_credential = matches!(case, Case::TamperedSignature | Case::WrongIssuer);
        if invalid_credential { assert!(human.is_none()); }
        else {
            let human = human.as_ref().unwrap();
            assert_eq!(human.principal().unwrap(), selected_human());
            assert_eq!(human.subject(), SUBJECT);
            assert_eq!(human.issuer(), ISSUER);
            assert_eq!(human.login_scope(), Some(if matches!(case, Case::MismatchedScope) { "another-login" } else { SCOPE }));
            assert!(human.current().is_ok());
        }
        let app = runtime.build_reference_app_router(decisions);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        server = Some((stop, tokio::spawn(async move {
            axum::serve(listener, app).with_graceful_shutdown(async { let _ = stopped.await; }).await
        })));
        if matches!(case, Case::Retired) {
            let retired = tokio::time::timeout(WAIT, logins.fixture_retire(1).unwrap())
                .await.expect("bounded Console login retirement").unwrap();
            assert!(retired.fenced && retired.reservations_drained && !retired.uncertain);
        }
        let reply = if matches!(case, Case::RetiredAfterSelection) {
            let retirement = async {
                let permit = tokio::time::timeout(WAIT, observation.entered.acquire()).await.unwrap().unwrap();
                permit.forget();
                assert_eq!(observation.selected.load(Ordering::SeqCst), 1);
                let retired = tokio::time::timeout(WAIT, logins.fixture_retire(1).unwrap())
                    .await.expect("bounded Console login retirement").unwrap();
                assert!(retired.fenced && retired.reservations_drained && !retired.uncertain);
                assert!(human.as_ref().unwrap().current().is_ok(), "valid token does not replace retired login");
                observation.release.add_permits(1);
            };
            let (reply, ()) = tokio::join!(post(address, &bearer, &member), retirement);
            reply
        } else { post(address, &bearer, &member).await };
        if matches!(case, Case::Valid | Case::RetiredAfterSelection) {
            let permit = tokio::time::timeout(WAIT, observation.finished.acquire()).await.unwrap().unwrap();
            permit.forget();
        }
        if matches!(case, Case::Valid) {
            assert!((200..300).contains(&reply.0), "normal Console send must succeed");
            assert!(observation.failure.lock().unwrap().is_none());
            assert_eq!(observation.selected.load(Ordering::SeqCst), 1);
            let bound = observation.bound.lock().unwrap().clone().unwrap();
            assert!(bound.header().authority_association.is_some());
            let raw = observation.raw.lock().unwrap().clone().unwrap();
            assert_eq!(bound.id(), raw.id());
            assert!(raw.header().idempotency_key.is_some());
            assert_eq!(bound.header().idempotency_key, raw.header().idempotency_key);
            tokio::time::timeout(WAIT, async {
                while fixture.inputs().await != Ok(1) || fixture.model_requests() == 0 { tokio::task::yield_now().await; }
            }).await.expect("actual Console input and controller inference");
            assert_eq!(fixture.model_requests(), 1);
            let observed = observation.human.lock().unwrap().clone().unwrap();
            assert_eq!(observed.principal().unwrap(), selected_human());
            assert_eq!(observed.login_scope(), Some(SCOPE));
            let rows = fixture.store.list_records(&fixture.scope, None, 100).await.unwrap();
            assert!(rows.len() > before_rows.len(), "actual Console source was retained");
        } else {
            if matches!(case, Case::RetiredAfterSelection) {
                assert!(observation.failure.lock().unwrap().is_some(), "retained login refuses inside actual binder");
                // Queue acknowledgement is not an admission receipt. The actual
                // completed binder refusal and native/store observations decide.
            } else { assert!((400..500).contains(&reply.0), "pre-entry refusal must not return HTTP success"); }
            assert_eq!(fixture.inputs().await, Ok(0));
            assert_eq!(fixture.model_requests(), 0);
            assert!(observation.bound.lock().unwrap().is_none());
            assert_eq!(std::fs::read(&grant_path).unwrap(), before_grants);
            assert_eq!(fixture.store.list_records(&fixture.scope, None, 100).await.unwrap(), before_rows);
            assert_eq!(observation.attempted.load(Ordering::SeqCst), usize::from(!invalid_credential));
            assert_eq!(observation.selected.load(Ordering::SeqCst), usize::from(matches!(case, Case::RetiredAfterSelection)));
        }
        drop(connection);
    })).catch_unwind().await;

    // On every assertion path release the test gate, stop and join the HTTP
    // owner, then join the actual native fixture before resuming a panic.
    observation.release.add_permits(1);
    let server_cleanup = if let Some((stop, mut task)) = server {
        let _ = stop.send(());
        match tokio::time::timeout(WAIT, &mut task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(format!("Console fixture server cleanup: {error}")),
            Ok(Err(error)) => Err(format!("Console fixture server join: {error}")),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err("Console fixture server cleanup timed out".to_owned())
            }
        }
    } else { Ok(()) };
    let native_cleanup = fixture.shutdown().await;
    assert!(server_cleanup.is_ok(), "{server_cleanup:?}");
    assert!(native_cleanup.is_ok(), "{native_cleanup:?}");
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_verifier_and_normal_console_send_admit_exact_enrolled_human() { controlled_console(Case::Valid).await; }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_login_refuses_normal_console_send_without_admission() { controlled_console(Case::Retired).await; }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_login_retired_after_native_selection_refuses_without_admission() { controlled_console(Case::RetiredAfterSelection).await; }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_mismatched_login_refuses_normal_console_send_without_admission() { controlled_console(Case::MismatchedScope).await; }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_signature_never_selects_installed_console_ingress() { controlled_console(Case::TamperedSignature).await; }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_issuer_never_selects_installed_console_ingress() { controlled_console(Case::WrongIssuer).await; }
