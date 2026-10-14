//! Agent Plugins 1.0.0 metadata import. Parsing never imports executable code,
//! launches servers, expands ambient environment variables, or grants authority.
//! Format source: https://agent-plugins.org/specification (checked 2026-09-29).

use crate::{
    ContentDigest, IntegrationPackage, PackageIdentity, PortableMcpEntry, RemoteTransport, ValidatedManifest,
    ValidationError, strict_mcpb_json,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use url::Url;

pub const AGENT_PLUGIN_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
pub const AGENT_PLUGIN_MCP_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";
pub const TOOLKIT_NAMESPACE: &str = "ai.rkat.toolkit";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginAuthor {
    pub name: Option<String>,
    pub email: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPluginManifest {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub author: Option<PluginAuthor>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub license: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Unknown namespaces remain opaque, including their value types.
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedPluginManifest {
    pub manifest: AgentPluginManifest,
    pub diagnostics: Vec<ImportDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportDiagnostic {
    pub scope: String,
    pub message: String,
}

impl ImportedPluginManifest {
    /// Agent Plugins ignores unknown top-level fields, but never grants them
    /// semantics. Wrong recognized field types still reject the manifest.
    pub fn parse(bytes: &[u8]) -> Result<Self, ValidationError> {
        // Reject ambiguity before Value can erase a conflicting declaration,
        // including one inside an otherwise opaque extension namespace.
        let mut value = strict_mcpb_json(bytes)
            .map_err(|_| ValidationError::new("plugin.json", "invalid or duplicate-key JSON"))?;
        let fields = value
            .as_object_mut()
            .ok_or_else(|| ValidationError::new("plugin.json", "manifest must be an object"))?;
        let mut diagnostics = Vec::new();
        let known: BTreeSet<_> = [
            "$schema",
            "name",
            "version",
            "description",
            "author",
            "homepage",
            "repository",
            "license",
            "keywords",
            "extensions",
        ]
        .into();
        let unknown: Vec<_> = fields
            .keys()
            .filter(|key| !known.contains(key.as_str()))
            .cloned()
            .collect();
        for field in unknown {
            fields.remove(&field);
            diagnostics.push(ImportDiagnostic {
                scope: field,
                message: "Unknown top-level field ignored".into(),
            });
        }
        if fields
            .get("extensions")
            .is_some_and(|value| !value.is_object())
        {
            fields.remove("extensions");
            diagnostics.push(ImportDiagnostic {
                scope: "extensions".into(),
                message: "Non-object extensions ignored".into(),
            });
        }
        if let Some(author) = fields.get("author").and_then(Value::as_object)
            && author.values().any(|value| !value.is_string())
        {
            return Err(ValidationError::new(
                "plugin.json:author",
                "author fields must be strings",
            ));
        }
        // Optional typed values are not nullable in the portable specification.
        for (name, value) in fields.iter() {
            if value.is_null() {
                return Err(ValidationError::new(
                    format!("plugin.json:{name}"),
                    "recognized metadata fields cannot be null",
                ));
            }
        }
        let manifest: AgentPluginManifest = serde_json::from_value(value).map_err(|_| {
            ValidationError::new("plugin.json", "invalid recognized manifest field")
        })?;
        if manifest.schema != AGENT_PLUGIN_SCHEMA {
            return Err(ValidationError::new(
                "plugin.json:$schema",
                "unsupported Agent Plugins version",
            ));
        }
        let name = manifest.name.as_bytes();
        if name.is_empty()
            || name.len() > 64
            || !name
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'.')
            || !name[0].is_ascii_alphanumeric()
            || !name[name.len() - 1].is_ascii_alphanumeric()
            || manifest.name.contains("--")
            || manifest.name.contains("..")
        {
            return Err(ValidationError::new(
                "plugin.json:name",
                "invalid portable plugin name",
            ));
        }
        Ok(Self {
            manifest,
            diagnostics,
        })
    }

    /// Toolkit extension validation is separate from portable component import.
    /// A generic client may ignore this namespace, so toolkit-dependent entries
    /// must not also appear as portable MCP entries.
    pub fn toolkit_package(&self) -> Result<Option<IntegrationPackage>, ValidationError> {
        let Some(value) = self.manifest.extensions.get(TOOLKIT_NAMESPACE) else {
            return Ok(None);
        };
        let package: IntegrationPackage = serde_json::from_value(value.clone()).map_err(|_| {
            ValidationError::new(TOOLKIT_NAMESPACE, "invalid toolkit package namespace")
        })?;
        package.validate()?;
        Ok(Some(package))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum PortableMcpServer {
    #[serde(rename = "stdio")]
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        cwd: Option<String>,
    },
    #[serde(rename = "streamable-http")]
    StreamableHttp {
        url: Url,
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },
    #[serde(rename = "sse")]
    LegacySse {
        url: Url,
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedMcpServers {
    pub servers: BTreeMap<String, PortableMcpServer>,
    pub diagnostics: Vec<ImportDiagnostic>,
}

impl ImportedMcpServers {
    /// Whole-file errors disable this component type. Individual invalid server
    /// entries are reported and skipped without discarding valid siblings.
    pub fn parse(bytes: &[u8]) -> Result<Self, ValidationError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Document {
            #[serde(rename = "$schema", default)]
            schema: Value,
            #[serde(rename = "mcpServers")]
            servers: Map<String, Value>,
        }
        // Duplicate keys are a document error, not a server fallback. Typed
        // validation below still isolates ordinary invalid sibling entries.
        let value = strict_mcpb_json(bytes)
            .map_err(|_| ValidationError::new("mcp.json", "invalid or duplicate-key JSON"))?;
        let document: Document = serde_json::from_value(value)
            .map_err(|_| ValidationError::new("mcp.json", "invalid MCP configuration document"))?;
        if document.schema.as_str() != Some(AGENT_PLUGIN_MCP_SCHEMA) {
            return Err(ValidationError::new(
                "mcp.json:$schema",
                "unsupported or mismatched Agent Plugins version",
            ));
        }
        let mut result = Self {
            servers: BTreeMap::new(),
            diagnostics: Vec::new(),
        };
        for (name, value) in document.servers {
            let parsed = serde_json::from_value::<PortableMcpServer>(value)
                .map_err(|_| ValidationError::new("server", "invalid server variant or fields"))
                .and_then(|server| {
                    server.validate()?;
                    Ok(server)
                });
            match parsed {
                Ok(server) => {
                    result.servers.insert(name, server);
                }
                Err(error) => result.diagnostics.push(ImportDiagnostic {
                    scope: name,
                    message: error.message,
                }),
            }
        }
        Ok(result)
    }
}

impl PortableMcpServer {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Stdio {
                command,
                args,
                env,
                cwd,
            } => {
                if command.is_empty()
                    || command.chars().any(|c| c.is_whitespace() || c.is_control())
                    || command.contains("${")
                {
                    return Err(ValidationError::new(
                        "command",
                        "command must be one literal executable token",
                    ));
                }
                if command.starts_with("./") {
                    relative_path(command)?;
                } else if command.contains('/') || command.contains('\\') || command.contains(':') {
                    return Err(ValidationError::new(
                        "command",
                        "command must be a bare executable or plugin-relative path",
                    ));
                }
                if env.keys().any(|key| {
                    key.eq_ignore_ascii_case("PLUGIN_ROOT")
                        || key.eq_ignore_ascii_case("PLUGIN_DATA")
                }) {
                    return Err(ValidationError::new(
                        "env",
                        "reserved plugin environment variables are host supplied",
                    ));
                }
                if args
                    .iter()
                    .chain(env.values())
                    .any(|value| value.contains('\0'))
                    || env
                        .keys()
                        .any(|key| key.is_empty() || key.contains('=') || key.contains('\0'))
                {
                    return Err(ValidationError::new(
                        "stdio",
                        "invalid subprocess argument or environment string",
                    ));
                }
                if let Some(cwd) = cwd {
                    if cwd.starts_with("./") {
                        relative_path(cwd)?;
                    } else if cwd != "${PLUGIN_ROOT}" && cwd != "${PLUGIN_DATA}" {
                        let tail = cwd
                            .strip_prefix("${PLUGIN_ROOT}/")
                            .or_else(|| cwd.strip_prefix("${PLUGIN_DATA}/"))
                            .ok_or_else(|| {
                                ValidationError::new(
                                    "cwd",
                                    "working directory must be rooted in plugin or plugin data",
                                )
                            })?;
                        relative_path(&format!("./{tail}"))?;
                    }
                }
            }
            Self::StreamableHttp { url, headers } | Self::LegacySse { url, headers } => {
                crate::manifest::validate_url(url, "url", false)?;
                let mut names = BTreeSet::new();
                for (name, value) in headers {
                    if name.is_empty()
                        || !name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                        || !value.bytes().all(|b| b == b'\t' || b >= 32 && b != 127)
                        || !names.insert(name.to_ascii_lowercase())
                    {
                        return Err(ValidationError::new(
                            "headers",
                            "invalid or case-duplicate HTTP header",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Portable Agent Plugins files built from validated import-side values.
/// Every document is re-imported before it is returned, so a generic client
/// reads exactly the values that were selected. Export never expands
/// placeholders, reads ambient environment, resolves credentials or launches a
/// server. The derived `Serialize` encodings stay as they are: they feed
/// retained bundle digests and are not portable documents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortablePluginExport {
    plugin_json: Vec<u8>,
    mcp_json: Option<Vec<u8>>,
    files: BTreeMap<String, Vec<u8>>,
}

/// Current filesystem observations only, never an export or readiness receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableExportCheckState {
    Matches,
    Missing,
    Mismatch,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableExportFingerprint {
    pub sha256: ContentDigest,
    pub bytes: u64,
}

impl PortableExportFingerprint {
    fn of_bytes(bytes: &[u8]) -> Self {
        Self {
            sha256: ContentDigest::of_bytes(bytes),
            bytes: bytes.len() as u64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableExportFileCheck {
    pub state: PortableExportCheckState,
    pub expected: PortableExportFingerprint,
    pub observed: Option<PortableExportFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableExportInventoryCheck {
    pub state: PortableExportCheckState,
    /// Every expected directory was enumerated within the inspection limits.
    pub complete: bool,
    /// Unexpected entries in expected directories; their names are not returned.
    pub unexpected_entries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableExportCheck {
    pub state: PortableExportCheckState,
    pub files: BTreeMap<String, PortableExportFileCheck>,
    pub inventory: PortableExportInventoryCheck,
}

/// Why an export was refused. Nothing is written for a refused export.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortableExportError {
    #[error(transparent)]
    Invalid(#[from] ValidationError),
    #[error("unsupported portable export{}: {reason}", entry.as_ref().map(|e| format!(" of {e}")).unwrap_or_default())]
    Unsupported {
        entry: Option<String>,
        reason: UnsupportedPortableExport,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UnsupportedPortableExport {
    /// A toolkit package carries MCP entries without the validated selection
    /// that declares them independent of toolkit contracts.
    #[error("toolkit package entries need the validated selection that declares them portable")]
    SelectionRequired,
    #[error("a selection can only declare entries of a toolkit package")]
    SelectionWithoutToolkitPackage,
    #[error("the selection belongs to a different package or package content")]
    SelectionForAnotherPackage,
    /// Includes every toolkit-dependent component: selection validation never
    /// declares one portable.
    #[error("the entry is not declared portable by the selection")]
    UndeclaredEntry,
    #[error("a declared portable entry is missing from the export")]
    MissingDeclaredEntry,
    #[error("the entry's transport or endpoint differs from its selected component")]
    ComponentMismatch,
    #[error("artifact realization into the plugin root is not exported")]
    ArtifactRealization,
    #[error("generated plugin documents cannot be replaced by an included file")]
    ReservedFile,
}

const PLUGIN_FILE: &str = "./plugin.json";
const MCP_FILE: &str = "./mcp.json";
const MAX_EXPORT_FILE_BYTES: u64 = 1024 * 1024;

impl PortablePluginExport {
    /// Export a plugin manifest and its portable MCP entries. A manifest with a
    /// toolkit package exports entries only when `selection` validated them as
    /// independent of toolkit contracts; every declared entry must be present
    /// and match its component exactly. A manifest without a toolkit package
    /// has no toolkit semantics to lose, so its validated entries export as is.
    pub fn new(
        manifest: &AgentPluginManifest,
        servers: &BTreeMap<String, PortableMcpServer>,
        selection: Option<&ValidatedManifest>,
    ) -> Result<Self, PortableExportError> {
        let export = Self::encode(manifest, servers)?;
        let package = ImportedPluginManifest {
            manifest: manifest.clone(),
            diagnostics: Vec::new(),
        }
        .toolkit_package()?;
        match (package, selection) {
            (None, None) => {}
            (Some(_), None) if servers.is_empty() => {}
            (Some(_), None) => {
                return Err(unsupported(
                    None,
                    UnsupportedPortableExport::SelectionRequired,
                ));
            }
            (None, Some(_)) => {
                return Err(unsupported(
                    None,
                    UnsupportedPortableExport::SelectionWithoutToolkitPackage,
                ));
            }
            (Some(package), Some(selection)) => {
                let selected = selection.manifest();
                let components = selected.components.iter().map(crate::manifest::ComponentContract::from).collect::<Vec<_>>();
                check_selected_entries(&package, servers, &selected.package,
                    &selected.package_content_digest, &components, &selected.portable_mcp_entries)?;
            }
        }
        Ok(export)
    }

    pub(crate) fn from_remote_declaration(
        manifest: &AgentPluginManifest,
        servers: &BTreeMap<String, PortableMcpServer>,
        validated: &crate::remote_export::ValidatedRemoteExportDeclaration,
    ) -> Result<Self, PortableExportError> {
        let export = Self::encode(manifest, servers)?;
        let package = ImportedPluginManifest { manifest: manifest.clone(), diagnostics: Vec::new() }
            .toolkit_package()?.ok_or_else(|| unsupported(None,
                UnsupportedPortableExport::SelectionWithoutToolkitPackage))?;
        let selected = validated.declaration();
        let components = selected.components.iter().map(crate::manifest::ComponentContract::from).collect::<Vec<_>>();
        check_selected_entries(&package, servers, &selected.package,
            &selected.package_content_digest, &components, &selected.portable_mcp_entries)?;
        Ok(export)
    }

    /// Encoding is private so every public export passes the selection rule.
    fn encode(
        manifest: &AgentPluginManifest,
        servers: &BTreeMap<String, PortableMcpServer>,
    ) -> Result<Self, PortableExportError> {
        for (name, server) in servers {
            server.validate().map_err(|error| {
                ValidationError::new(format!("mcp.json:{name}:{}", error.path), error.message)
            })?;
        }
        let plugin_json = serde_json::to_vec_pretty(&portable_manifest_value(manifest))
            .map_err(|_| ValidationError::new("plugin.json", "cannot encode manifest"))?;
        let reimported = ImportedPluginManifest::parse(&plugin_json)?;
        if !reimported.diagnostics.is_empty() || &reimported.manifest != manifest {
            return Err(ValidationError::new(
                "plugin.json",
                "manifest does not survive portable re-import unchanged",
            )
            .into());
        }
        let mcp_json = if servers.is_empty() {
            None
        } else {
            let document = serde_json::json!({
                "$schema": AGENT_PLUGIN_MCP_SCHEMA,
                "mcpServers": servers
                    .iter()
                    .map(|(name, server)| (name.clone(), portable_server_value(server)))
                    .collect::<Map<_, _>>(),
            });
            let bytes = serde_json::to_vec_pretty(&document)
                .map_err(|_| ValidationError::new("mcp.json", "cannot encode MCP entries"))?;
            let reimported = ImportedMcpServers::parse(&bytes)?;
            if !reimported.diagnostics.is_empty() || &reimported.servers != servers {
                return Err(ValidationError::new(
                    "mcp.json",
                    "MCP entries do not survive portable re-import unchanged",
                )
                .into());
            }
            Some(bytes)
        };
        Ok(Self {
            plugin_json,
            mcp_json,
            files: BTreeMap::new(),
        })
    }

    /// Include an inert file, such as a skill document, read through the
    /// anchored plugin root. Its bytes are copied exactly and never parsed.
    pub fn with_file(
        mut self,
        root: &PluginRoot,
        relative: &str,
    ) -> Result<Self, PortableExportError> {
        let path = format!("./{}", relative_path(relative)?);
        if path == PLUGIN_FILE || path == MCP_FILE {
            return Err(unsupported(
                Some(path),
                UnsupportedPortableExport::ReservedFile,
            ));
        }
        let bytes = root.read(&path, MAX_EXPORT_FILE_BYTES)?;
        self.files.insert(path, bytes);
        Ok(self)
    }

    pub fn plugin_json(&self) -> &[u8] {
        &self.plugin_json
    }

    pub fn mcp_json(&self) -> Option<&[u8]> {
        self.mcp_json.as_deref()
    }

    pub fn files(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
    }

    /// Compare existing files with these exact canonical bytes without writing.
    ///
    /// Unix inspections reject symlinks and special files, bound reads and
    /// inventory traversal, and recheck observed identities. Other platforms
    /// fail closed as unavailable. The host must retain exclusive directory
    /// custody and control its ancestors; this is not an atomic snapshot against
    /// external writers, proof of historical export, or endpoint readiness.
    pub fn inspect_existing(&self, destination: impl AsRef<Path>) -> PortableExportCheck {
        let expected: BTreeMap<_, _> = [
            (PLUGIN_FILE, Some(self.plugin_json())),
            (MCP_FILE, self.mcp_json()),
        ]
        .into_iter()
        .filter_map(|(path, bytes)| bytes.map(|bytes| (path, bytes)))
        .chain(self.files())
        .map(|(path, bytes)| {
            (
                path.strip_prefix("./")
                    .expect("portable relative path")
                    .to_owned(),
                bytes,
            )
        })
        .collect();
        let check = PortableExportCheck {
            state: PortableExportCheckState::Unavailable,
            files: expected
                .iter()
                .map(|(path, bytes)| {
                    (
                        path.clone(),
                        PortableExportFileCheck {
                            state: PortableExportCheckState::Unavailable,
                            expected: PortableExportFingerprint::of_bytes(bytes),
                            observed: None,
                        },
                    )
                })
                .collect(),
            inventory: PortableExportInventoryCheck {
                state: PortableExportCheckState::Unavailable,
                complete: false,
                unexpected_entries: 0,
            },
        };
        #[cfg(unix)]
        {
            export_inspection::inspect(destination.as_ref(), &expected, check)
        }
        #[cfg(not(unix))]
        {
            let _ = destination;
            check
        }
    }

    /// Write into a new directory. Writes stay anchored to that directory and
    /// never replace an existing file; an existing destination is refused.
    pub fn write_new(&self, destination: impl AsRef<Path>) -> Result<(), ValidationError> {
        use std::io::Write;
        std::fs::create_dir(destination.as_ref()).map_err(|_| {
            ValidationError::new("export destination", "destination must be a new directory")
        })?;
        let directory =
            cap_std::fs::Dir::open_ambient_dir(destination.as_ref(), cap_std::ambient_authority())
                .map_err(|_| {
                    ValidationError::new("export destination", "cannot open destination")
                })?;
        let documents = [
            (PLUGIN_FILE, Some(self.plugin_json.as_slice())),
            (MCP_FILE, self.mcp_json.as_deref()),
        ];
        let files = documents
            .into_iter()
            .filter_map(|(path, bytes)| bytes.map(|bytes| (path, bytes)))
            .chain(self.files());
        for (path, bytes) in files {
            let relative = relative_path(path)?;
            if let Some(parent) = Path::new(relative)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
            {
                directory.create_dir_all(parent).map_err(|_| {
                    ValidationError::new("export destination", "cannot create export directory")
                })?;
            }
            let mut options = cap_std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            directory
                .open_with(relative, &options)
                .and_then(|mut file| file.write_all(bytes))
                .map_err(|_| {
                    ValidationError::new("export destination", "cannot write export file")
                })?;
        }
        Ok(())
    }
}

#[cfg(unix)]
mod export_inspection {
    use super::{
        MAX_EXPORT_FILE_BYTES, PortableExportCheck, PortableExportCheckState as State,
        PortableExportFingerprint, PortableExportInventoryCheck,
    };
    use cap_std::fs::{Dir, Metadata, MetadataExt, OpenOptions, OpenOptionsExt};
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::{self, Read};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    const MAX_FILES: usize = 128;
    const MAX_ENTRIES: usize = 512;
    const MAX_DEPTH: usize = 32;
    const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;

    #[derive(Debug, PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        mode: u32,
        bytes: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    fn stamp(metadata: &Metadata) -> Stamp {
        Stamp {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            bytes: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    fn options(directory: bool) -> OpenOptions {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_NOFOLLOW | libc::O_NONBLOCK | if directory { libc::O_DIRECTORY } else { 0 },
        );
        options
    }

    fn open_directory(parent: &Dir, name: &Path) -> io::Result<Dir> {
        let before = parent.symlink_metadata(name)?;
        if !before.is_dir() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let file = parent.open_with(name, &options(true))?;
        if stamp(&before) != stamp(&file.metadata()?) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Dir::from_std_file(file.into_std()))
    }

    fn inventory(
        root: &Dir,
        directories: &BTreeSet<PathBuf>,
    ) -> io::Result<BTreeMap<PathBuf, Stamp>> {
        let mut found = BTreeMap::new();
        let mut pending = vec![(PathBuf::new(), root.try_clone()?)];
        while let Some((prefix, directory)) = pending.pop() {
            for entry in directory.entries()? {
                if found.len() >= MAX_ENTRIES {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                let name = entry?.file_name();
                let path = prefix.join(&name);
                let metadata = directory.symlink_metadata(&name)?;
                if !metadata.is_file() && !metadata.is_dir() {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                if found.insert(path.clone(), stamp(&metadata)).is_some() {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                if directories.contains(&path) {
                    pending.push((path, open_directory(&directory, Path::new(&name))?));
                }
                // An unexpected directory already proves a mismatch. Do not
                // traverse its unknown, potentially unbounded subtree.
            }
        }
        Ok(found)
    }

    fn read_expected(
        root: &Dir,
        path: &Path,
        expected: &[u8],
        remaining: &mut u64,
    ) -> io::Result<(State, Option<PortableExportFingerprint>)> {
        let mut directory = root.try_clone()?;
        let mut parts = path.iter().peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_some() {
                directory = open_directory(&directory, Path::new(part))?;
                continue;
            }
            let before = directory.symlink_metadata(part)?;
            if !before.is_file() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let file = directory.open_with(part, &options(false))?;
            if stamp(&before) != stamp(&file.metadata()?) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let limit = MAX_EXPORT_FILE_BYTES.min(*remaining);
            let result = if before.len() > limit {
                let state = if before.len() > MAX_EXPORT_FILE_BYTES
                    && before.len() != expected.len() as u64
                {
                    State::Mismatch
                } else {
                    State::Unavailable
                };
                (state, None)
            } else {
                let mut bytes = Vec::new();
                let read = (&file).take(limit).read_to_end(&mut bytes);
                // Charge partial reads too. The final metadata checks detect
                // growth without an extra byte beyond the shared read budget.
                *remaining -= bytes.len() as u64;
                read?;
                (
                    if bytes == expected {
                        State::Matches
                    } else {
                        State::Mismatch
                    },
                    Some(PortableExportFingerprint::of_bytes(&bytes)),
                )
            };
            if stamp(&before) != stamp(&file.metadata()?)
                || stamp(&before) != stamp(&directory.symlink_metadata(part)?)
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            return Ok(result);
        }
        Err(io::ErrorKind::InvalidInput.into())
    }

    pub(super) fn inspect(
        destination: &Path,
        expected: &BTreeMap<String, &[u8]>,
        mut check: PortableExportCheck,
    ) -> PortableExportCheck {
        // Path components normalize away trailing separators and dots. Inspect
        // the original spelling so O_NOFOLLOW protects the actual final entry.
        let raw = destination.as_os_str().as_bytes();
        if raw.contains(&0)
            || raw
                .split(|byte| *byte == b'/')
                .enumerate()
                .any(|(index, part)| {
                    (part.is_empty() && !(index == 0 && raw.starts_with(b"/")))
                        || part == b"."
                        || part == b".."
                })
        {
            return check;
        }
        let mut directories = BTreeSet::new();
        let mut nodes = BTreeSet::new();
        for name in expected.keys() {
            if name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
                || name.split('/').count() > MAX_DEPTH
            {
                return check;
            }
            let path = Path::new(name);
            nodes.insert(path.to_owned());
            for parent in path
                .ancestors()
                .skip(1)
                .filter(|p| !p.as_os_str().is_empty())
            {
                directories.insert(parent.to_owned());
                nodes.insert(parent.to_owned());
            }
        }
        if expected.len() > MAX_FILES || nodes.len() > MAX_ENTRIES {
            return check;
        }
        let metadata = match std::fs::symlink_metadata(destination) {
            Ok(metadata) if metadata.is_dir() => Metadata::from_just_metadata(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                check.state = State::Missing;
                check.inventory.state = State::Missing;
                check.inventory.complete = true;
                for file in check.files.values_mut() {
                    file.state = State::Missing;
                }
                return check;
            }
            _ => return check,
        };
        use std::os::unix::fs::OpenOptionsExt as _;
        let root = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY)
            .open(destination)
        {
            Ok(file) => Dir::from_std_file(file),
            Err(_) => return check,
        };
        let stable_root = || {
            root.dir_metadata()
                .is_ok_and(|current| stamp(&current) == stamp(&metadata))
                && std::fs::symlink_metadata(destination).is_ok_and(|current| {
                    stamp(&Metadata::from_just_metadata(current)) == stamp(&metadata)
                })
        };
        if !stable_root() {
            return check;
        }
        let Ok(before) = inventory(&root, &directories) else {
            return check;
        };
        let unexpected = before.keys().filter(|path| !nodes.contains(*path)).count() as u64;
        let missing = nodes.iter().any(|path| !before.contains_key(path));
        check.inventory = PortableExportInventoryCheck {
            state: if unexpected > 0 {
                State::Mismatch
            } else if missing {
                State::Missing
            } else {
                State::Matches
            },
            complete: true,
            unexpected_entries: unexpected,
        };
        let mut remaining = MAX_TOTAL_BYTES;
        for (name, expected) in expected {
            let file = check.files.get_mut(name).expect("canonical expected file");
            match read_expected(&root, Path::new(name), expected, &mut remaining) {
                Ok((state, observed)) => {
                    file.state = state;
                    file.observed = observed;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    file.state = State::Missing
                }
                Err(_) => {}
            }
        }
        if !inventory(&root, &directories).is_ok_and(|after| before == after) || !stable_root() {
            check.inventory.state = State::Unavailable;
            check.inventory.complete = false;
            for file in check.files.values_mut() {
                file.state = State::Unavailable;
                file.observed = None;
            }
        }
        check.state = check
            .files
            .values()
            .fold(check.inventory.state, |state, file| state.max(file.state));
        check
    }
}

fn unsupported(entry: Option<String>, reason: UnsupportedPortableExport) -> PortableExportError {
    PortableExportError::Unsupported { entry, reason }
}

fn check_selected_entries(
    package: &IntegrationPackage,
    servers: &BTreeMap<String, PortableMcpServer>,
    selected_package: &PackageIdentity,
    selected_digest: &ContentDigest,
    components: &[crate::manifest::ComponentContract],
    portable_mcp_entries: &[PortableMcpEntry],
) -> Result<(), PortableExportError> {
    if selected_package != &package.identity
        || selected_digest != &package.content_digest()?
    {
        return Err(unsupported(
            None,
            UnsupportedPortableExport::SelectionForAnotherPackage,
        ));
    }
    let declared: BTreeMap<&str, _> = portable_mcp_entries
        .iter()
        .filter_map(|entry| {
            components
                .iter()
                .find(|component| component.id == entry.component)
                .map(|component| (entry.name.as_str(), component))
        })
        .collect();
    if let Some(missing) = declared.keys().find(|name| !servers.contains_key(**name)) {
        return Err(unsupported(
            Some((*missing).to_owned()),
            UnsupportedPortableExport::MissingDeclaredEntry,
        ));
    }
    for (name, server) in servers {
        let component = declared.get(name.as_str()).ok_or_else(|| {
            unsupported(
                Some(name.clone()),
                UnsupportedPortableExport::UndeclaredEntry,
            )
        })?;
        match (&component.source, server) {
            (
                crate::manifest::ContractSource::RemoteService {
                    endpoint,
                    transport: RemoteTransport::McpStreamableHttp,
                    ..
                },
                PortableMcpServer::StreamableHttp { url, .. },
            ) if url == endpoint => {}
            (crate::manifest::ContractSource::Artifact { .. }, _) => {
                return Err(unsupported(
                    Some(name.clone()),
                    UnsupportedPortableExport::ArtifactRealization,
                ));
            }
            _ => {
                return Err(unsupported(
                    Some(name.clone()),
                    UnsupportedPortableExport::ComponentMismatch,
                ));
            }
        }
    }
    Ok(())
}

/// Absent optional fields stay absent: the portable format does not accept
/// null for recognized fields. Unknown namespaces are copied verbatim.
fn portable_manifest_value(manifest: &AgentPluginManifest) -> Value {
    let mut fields = Map::new();
    fields.insert("$schema".into(), Value::String(manifest.schema.clone()));
    fields.insert("name".into(), Value::String(manifest.name.clone()));
    insert_present(
        &mut fields,
        [
            ("version", &manifest.version),
            ("description", &manifest.description),
        ],
    );
    if let Some(author) = &manifest.author {
        let mut author_fields = Map::new();
        insert_present(
            &mut author_fields,
            [
                ("name", &author.name),
                ("email", &author.email),
                ("url", &author.url),
            ],
        );
        fields.insert("author".into(), Value::Object(author_fields));
    }
    insert_present(
        &mut fields,
        [
            ("homepage", &manifest.homepage),
            ("repository", &manifest.repository),
            ("license", &manifest.license),
        ],
    );
    if !manifest.keywords.is_empty() {
        fields.insert("keywords".into(), Value::from(manifest.keywords.clone()));
    }
    if !manifest.extensions.is_empty() {
        fields.insert(
            "extensions".into(),
            Value::Object(manifest.extensions.clone().into_iter().collect()),
        );
    }
    Value::Object(fields)
}

fn insert_present<'a>(
    fields: &mut Map<String, Value>,
    values: impl IntoIterator<Item = (&'a str, &'a Option<String>)>,
) {
    for (name, value) in values {
        if let Some(value) = value {
            fields.insert(name.into(), Value::String(value.clone()));
        }
    }
}

/// Placeholders such as `${PLUGIN_ROOT}` remain literal strings for the client.
fn portable_server_value(server: &PortableMcpServer) -> Value {
    let mut fields = Map::new();
    match server {
        PortableMcpServer::Stdio {
            command,
            args,
            env,
            cwd,
        } => {
            fields.insert("type".into(), "stdio".into());
            fields.insert("command".into(), Value::String(command.clone()));
            if !args.is_empty() {
                fields.insert("args".into(), Value::from(args.clone()));
            }
            if !env.is_empty() {
                fields.insert("env".into(), string_map(env));
            }
            if let Some(cwd) = cwd {
                fields.insert("cwd".into(), Value::String(cwd.clone()));
            }
        }
        PortableMcpServer::StreamableHttp { url, headers }
        | PortableMcpServer::LegacySse { url, headers } => {
            let kind = if matches!(server, PortableMcpServer::LegacySse { .. }) {
                "sse"
            } else {
                "streamable-http"
            };
            fields.insert("type".into(), kind.into());
            fields.insert("url".into(), Value::String(url.as_str().to_owned()));
            if !headers.is_empty() {
                fields.insert("headers".into(), string_map(headers));
            }
        }
    }
    Value::Object(fields)
}

fn string_map(values: &BTreeMap<String, String>) -> Value {
    Value::Object(
        values
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect(),
    )
}

/// A resolved directory is a read boundary, not an executable authorization.
/// Backends must verify selected bytes again when realizing an immutable artifact.
#[derive(Debug)]
pub struct PluginRoot {
    directory: cap_std::fs::Dir,
}

impl PluginRoot {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ValidationError> {
        let directory = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())
            .map_err(|_| {
                ValidationError::new("plugin root", "cannot open plugin root directory")
            })?;
        Ok(Self { directory })
    }

    /// Open a selected directory below an already trusted root. Subsequent
    /// reads stay anchored to this directory even if its path is replaced.
    pub fn open_relative(&self, relative: &str) -> Result<Self, ValidationError> {
        let relative = relative_path(relative)?;
        let directory = self.directory.open_dir(relative).map_err(|_| {
            ValidationError::new(
                "plugin root",
                "directory is absent or escapes the trusted root",
            )
        })?;
        Ok(Self { directory })
    }

    /// This is a diagnostic relative path, never an authorization to reopen
    /// through ambient filesystem APIs. Reads below stay anchored to the handle.
    pub fn resolve(&self, relative: &str) -> Result<PathBuf, ValidationError> {
        let relative = relative_path(relative)?;
        self.directory.canonicalize(relative).map_err(|_| {
            ValidationError::new("package path", "path is absent or escapes the plugin root")
        })
    }

    pub fn read(&self, relative: &str, maximum_bytes: u64) -> Result<Vec<u8>, ValidationError> {
        use std::io::Read;
        let relative = relative_path(relative)?;
        // Reject special files before opening them. The descriptor check below
        // also handles replacement between this check and the anchored open.
        if !self
            .directory
            .metadata(relative)
            .map_err(|_| ValidationError::new("package path", "cannot inspect package file"))?
            .is_file()
        {
            return Err(ValidationError::new(
                "package path",
                "package path is not a regular file",
            ));
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true);
        // A file can be replaced with a FIFO after the metadata check. Opening
        // nonblocking lets us inspect that actual descriptor without waiting
        // for a writer. O_NONBLOCK has no effect on regular file reads.
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = self
            .directory
            .open_with(relative, &options)
            .map_err(|_| ValidationError::new("package path", "cannot read package file"))?;
        if !file
            .metadata()
            .map_err(|_| ValidationError::new("package path", "cannot inspect package file"))?
            .is_file()
        {
            return Err(ValidationError::new(
                "package path",
                "package path is not a regular file",
            ));
        }
        let mut bytes = Vec::new();
        file.take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| ValidationError::new("package path", "cannot read package file"))?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(ValidationError::new(
                "package path",
                "package metadata exceeds the read limit",
            ));
        }
        Ok(bytes)
    }

    pub fn read_manifest(&self) -> Result<ImportedPluginManifest, ValidationError> {
        ImportedPluginManifest::parse(&self.read("./plugin.json", 1024 * 1024)?)
    }
}

fn relative_path(value: &str) -> Result<&str, ValidationError> {
    let path = value.strip_prefix("./").ok_or_else(|| {
        ValidationError::new("package path", "plugin-relative path must start with ./")
    })?;
    if path.contains('\\')
        || path.contains('\0')
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part == ".." || part.contains(':'))
    {
        return Err(ValidationError::new(
            "package path",
            "unsafe plugin-relative path",
        ));
    }
    Ok(path)
}

/// Single-pass replacement: inserted path text is never recursively expanded.
/// Unknown placeholders and shell syntax remain literal.
pub fn expand_plugin_placeholders(value: &str, root: &str, data: &str) -> String {
    let mut output = String::new();
    let mut remaining = value;
    while let Some(position) = remaining.find("${PLUGIN_") {
        output.push_str(&remaining[..position]);
        remaining = &remaining[position..];
        if let Some(tail) = remaining.strip_prefix("${PLUGIN_ROOT}") {
            output.push_str(root);
            remaining = tail;
        } else if let Some(tail) = remaining.strip_prefix("${PLUGIN_DATA}") {
            output.push_str(data);
            remaining = tail;
        } else {
            output.push_str("${PLUGIN_");
            remaining = &remaining[9..];
        }
    }
    output.push_str(remaining);
    output
}
