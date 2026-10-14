//! One live handoff owned by the actual installed preparation invocation.
//!
//! This does not establish installation, authentication, or native readiness.
use super::*;
use std::{future::Future, io, os::unix::fs::OpenOptionsExt};
use tokio::{io::{AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout}};

fn unavailable() -> ConnectError {
    ConnectError::InvalidInput("The next local setup round is unconfirmed. Retained requests remain available for readback; no automatic retry was started.".into())
}

/// A move-only owner derived by the same verified resource preparation.
/// It cannot be reconstructed from a model-visible path or saved descriptor.
/// Every new invocation reserves new preparation artifacts. A killed old owner
/// may leave a dead locator there; its old descriptor stays recovery-only.
pub struct LocalRoundOwner {
    resources: InstalledResources,
    artifacts: PathBuf,
    request: serde_json::Value,
    poisoned: bool,
}

/// Held across the actual native setup open. Every ordinary branch must await
/// settle or cancel; dropping closes the pipe and kills only this direct child.
#[must_use = "the entered local round owner must be settled or cancelled and joined"]
pub struct LocalRoundGuard<'a> {
    owner: &'a mut LocalRoundOwner,
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    request_path: PathBuf,
    request_raw: Vec<u8>,
}

fn exact_file(path: &Path) -> Result<Vec<u8>, ConnectError> {
    let file = fs::OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path).map_err(|_| unavailable())?;
    let metadata = file.metadata().map_err(|_| unavailable())?;
    if !metadata.is_file() || metadata.len() > MANIFEST_LIMIT || mode(&metadata) & 0o077 != 0 {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    Read::take(file, MANIFEST_LIMIT + 1).read_to_end(&mut bytes).map_err(|_| unavailable())?;
    if bytes.len() as u64 > MANIFEST_LIMIT { return Err(unavailable()); }
    Ok(bytes)
}

fn retain(path: &Path, raw: &[u8]) -> Result<(), ConnectError> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(path).map_err(|_| unavailable())?;
    file.write_all(raw).and_then(|_| file.sync_all()).map_err(|_| unavailable())
}

impl InstalledResources {
    /// The ordinary preparation result is unchanged. Only this current caller
    /// receives the live continuation owner before transferring the connection.
    pub async fn prepare_with_local_round_owner(
        self, storage: &meerkat_core::ResolvedStorage,
        cancelled: impl Future<Output = io::Result<()>>,
    ) -> Result<(PreparedResources, LocalRoundOwner), ConnectError> {
        let prepared = self.prepare_once(storage, cancelled).await?;
        let directory = prepared.artifact_directory.join("prepared");
        let descriptor = exact_file(&directory.join("product-mcp.json"))?;
        let preparation = exact_file(&directory.join("product-prepared.json"))?;
        let owner = LocalRoundOwner {
            resources: self,
            artifacts: prepared.artifact_directory.clone(),
            request: serde_json::json!({
                "prepared": directory,
                "realm_state_root": storage.locator.state_root,
                "realm": storage.locator.realm.as_str(),
                "descriptor_sha256": digest(&descriptor),
                "preparation_sha256": digest(&preparation),
            }),
            poisoned: false,
        };
        Ok((prepared, owner))
    }
}

impl LocalRoundOwner {
    /// Call only after the previous NativeSetup has actually closed and joined.
    /// Lock availability is an additional overlap check, not settlement proof.
    pub async fn begin(
        &mut self, cancelled: impl Future<Output = io::Result<()>>,
    ) -> Result<LocalRoundGuard<'_>, ConnectError> {
        if self.poisoned { return Err(unavailable()); }
        // This is invocation-local custody, not a persisted denial record.
        self.poisoned = true;
        self.check_resources()?;
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::Builder::new().prefix("round-")
            .permissions(fs::Permissions::from_mode(0o700)).tempdir_in(&self.artifacts)
            .map_err(|_| unavailable())?.keep();
        let request_path = directory.join("request.json");
        let request_raw = serde_json::to_vec(&self.request).map_err(|_| unavailable())?;
        retain(&request_path, &request_raw)?;
        let stderr = fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(directory.join("owner.stderr")).map_err(|_| unavailable())?;
        let mut child = tokio::process::Command::new(&self.resources.python)
            .args(["-I", "-B"]).arg(&self.resources.prepare)
            .arg("--destination").arg(directory.join("unused"))
            .arg("--local-round-owner").arg(&request_path)
            .current_dir(&self.resources.root).env_clear().env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::from(stderr))
            .kill_on_drop(true).spawn().map_err(|_| unavailable())?;
        let input = child.stdin.take();
        let output = child.stdout.take();
        let (Some(input), Some(output)) = (input, output) else {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(unavailable());
        };
        let mut guard = LocalRoundGuard { owner: self, child, input: Some(input),
            output: BufReader::new(output), request_path, request_raw };
        tokio::pin!(cancelled);
        let admitted = tokio::select! {
            result = read_ready(&mut guard.output) => result,
            _ = &mut cancelled => false,
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => false,
        };
        if !admitted {
            guard.cancel().await?;
            return Err(unavailable());
        }
        Ok(guard)
    }

    fn check_resources(&self) -> Result<(), ConnectError> {
        let current = InstalledResources::locate()?;
        if current.root != self.resources.root || current.prepare != self.resources.prepare
            || current.python != self.resources.python { return Err(unavailable()); }
        Ok(())
    }
}

impl LocalRoundGuard<'_> {
    /// A native object may already exist when this fails. Its actual owner must
    /// close and join it; an unconfirmed handoff is not an inferred rollback.
    pub async fn settle(mut self) -> Result<(), ConnectError> {
        let sent = match self.input.take() {
            Some(mut input) => input.write_all(b"{\"settle\":true}\n").await.is_ok(),
            None => false,
        };
        let mut raw = Vec::new();
        let read = (&mut self.output).take(4097).read_to_end(&mut raw).await;
        if read.is_err() || raw.len() > 4096 {
            // This coordinator owns no descendants. A broken fixed protocol
            // cannot leave its direct child blocked on an unread output pipe.
            let _ = self.child.start_kill();
            let _ = self.child.wait().await;
            return Err(unavailable());
        }
        let status = self.child.wait().await.map_err(|_| unavailable())?;
        if !sent || !status.success()
            || raw != b"{\"consumed\":true}\n{\"settled\":true}\n"
            || exact_file(&self.request_path)? != self.request_raw {
            return Err(unavailable());
        }
        self.owner.check_resources()?;
        self.owner.poisoned = false;
        Ok(())
    }

    /// Closing the live host pipe wakes the fixed owner, including while it is
    /// waiting on a helper. This method joins it without asserting consumption.
    pub async fn cancel(mut self) -> Result<(), ConnectError> {
        self.input.take();
        self.child.wait().await.map_err(|_| unavailable())?;
        Ok(())
    }
}

async fn read_ready(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> bool {
    let mut ready = [0_u8; 15];
    reader.read_exact(&mut ready).await.is_ok() && ready == *b"{\"ready\":true}\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn readiness_is_exact_and_refuses_oversized_unterminated_output_without_waiting_for_eof() {
        assert!(read_ready(&mut &b"{\"ready\":true}\n"[..]).await);
        for bytes in [&b"{\"ready\":false}"[..], &b"{\"ready\":true} "[..], &b"{\"ready\":tru"[..]] {
            assert!(!read_ready(&mut &bytes[..]).await);
        }
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        writer.write_all(&vec![b'x'; 4096]).await.unwrap();
        // Keep the writer live: no newline or EOF can release an unbounded
        // readline. The production fixed-size read must refuse immediately.
        assert!(!tokio::time::timeout(std::time::Duration::from_secs(1), read_ready(&mut reader))
            .await.expect("readiness must be bounded"));
        drop(writer);
    }
}
