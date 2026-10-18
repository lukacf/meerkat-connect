#!/usr/bin/env python3
"""Candidate-only CI composition of the existing Connect producer contracts.

No release/tag/registry operation, record sanitization or success substitution.
The unbound committed selection deliberately fails before any product execution.
"""
from pathlib import Path, PurePosixPath
import argparse
import email.parser
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "release/connect-release-inputs.json"
TARGET = "linux-x86_64"
SCOPE = "installed_gateway_schema4_resource_startup_and_shutdown_preview"
MAX_FILE = 2 * 1024**3 - 1
HEX = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
FORGE_READERS = {"installer/launchkit/runtime_selection.py",
                 "installer/launchkit/runtime_candidates.py",
                 "installer/launchkit/sdk_wheel_integrity.py",
                 "installer/launchkit/templates/install_candidate.py"}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def binding(path):
    return {"path": str(path), "size": path.stat().st_size, "sha256": digest(path)}


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        stream.write("\n")
    path.chmod(0o644)


def relative(value):
    require(isinstance(value, str) and value and "\\" not in value, "invalid relative locator")
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and ".." not in path.parts,
            "noncanonical relative locator")
    return value


def unbound(value):
    if value is None:
        return True
    if isinstance(value, dict):
        return any(unbound(item) for item in value.values())
    if isinstance(value, list):
        return any(unbound(item) for item in value)
    return False


def public_url(value):
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https" and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment, "public immutable HTTPS input required")
    github = (parsed.hostname == "github.com" and re.fullmatch(
        r"/(lukacf/(meerkat|meerkat-meta|meerkat-connect)|astral-sh/python-build-standalone)"
        r"/releases/download/[^/]+/[^/]+", parsed.path))
    pypi = parsed.hostname == "files.pythonhosted.org" and parsed.path.startswith("/packages/")
    node = parsed.hostname == "nodejs.org" and re.fullmatch(r"/dist/v[0-9.]+/[^/]+", parsed.path)
    require(github or pypi or node, "input URL is outside the selected public release hosts")


def source_state():
    def git(*args):
        return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()
    require(git("status", "--porcelain", "--untracked-files=normal") == "", "source checkout is dirty")
    revision = git("rev-parse", "HEAD")
    expected = os.environ.get("CONNECT_SOURCE_SHA", "")
    require(SHA.fullmatch(expected) and revision == expected == os.environ.get("GITHUB_SHA")
            == os.environ.get("GITHUB_WORKFLOW_SHA"), "dispatch, workflow and selected source differ")
    return revision, git("rev-parse", "HEAD^{tree}")


def preflight():
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and platform.system() == "Linux" and platform.machine() == "x86_64",
            "manual clean GitHub-hosted Linux execution required")
    require(os.environ.get("GITHUB_REPOSITORY") == "lukacf/meerkat-connect", "wrong candidate repository")
    revision, tree = source_state()
    expected = os.environ.get("CONNECT_INPUTS_SHA256", "")
    require(HEX.fullmatch(expected) and digest(INPUTS) == expected, "release input selection differs")
    value = read_json(INPUTS)
    require(not unbound(value), "unbound release inputs: no build or old-default fallback")
    require(value["schema_version"] == 1 and value["kind"] == "connect-linux-candidate-inputs"
            and value["target"] == TARGET and value["scope"] == SCOPE, "wrong candidate scope")
    require(VERSION.fullmatch(value["connect_version"]), "explicit Connect version required")
    native = tomllib.loads((ROOT / "native-candidate/Cargo.toml").read_text())
    sdk = tomllib.loads((ROOT / "sdk/python/pyproject.toml").read_text())["project"]
    require(native["workspace"]["package"]["version"] == value["connect_version"],
            "Connect version differs from source metadata")
    require(sdk["name"] == value["sdks"]["toolkit"]["distribution"]
            and sdk["version"] == value["sdks"]["toolkit"]["version"], "Connect SDK metadata differs")
    require(value["rust_toolchain"] == "1.97.0", "unreviewed Rust toolchain")
    for name, repository in (("core", "meerkat"), ("meta", "meerkat-meta")):
        selected = value["native_release"][name]
        require(selected["version"] == "0.9.4" and SHA.fullmatch(selected["source_sha"])
                and selected["repository"] == "lukacf/" + repository
                and selected["tag"] == "v0.9.4", "exact published Core/Meta 0.9.4 required")
    require(value["sdks"]["meta"]["version"] == "0.9.4", "Meta application SDK must match native release")
    require("meerkat-meta==0.9.4" in sdk.get("optional-dependencies", {}).get("native-host", []),
            "selected Connect SDK must declare the matching native-host dependency")
    require(set(value["forge_reader_source_pins"]) == FORGE_READERS
            and all(HEX.fullmatch(pin) for pin in value["forge_reader_source_pins"].values()),
            "exact published Meta reader source inventory required")
    files = value["files"]
    require(isinstance(files, dict) and 0 < len(files) <= 512, "bounded complete public file selection required")
    for name, row in files.items():
        relative(name)
        require(set(row) == {"url", "size", "sha256"} and type(row["size"]) is int
                and 0 < row["size"] <= MAX_FILE and HEX.fullmatch(row["sha256"]), "invalid public file pin")
        public_url(row["url"])
    references = list(value["resources"]["upstream"])
    references += [value["resources"][key] for key in ("library", "acquisition_node", "npm", "node_prebuilt_policy")]
    references += [value["dependencies"]["requirements"], *value["dependencies"]["wheels"]]
    references += [value["sdk_build"]["requirements"], *value["sdk_build"]["wheels"]]
    references += [value["sdks"]["meta"]["wheel"]]
    if value["resources"].get("node_build_profile"):
        references.append(value["resources"]["node_build_profile"])
    require(set(references) == set(files), "input inventory is incomplete or contains unselected files")
    require(0 < len(value["dependencies"]["wheels"]) <= 256, "offline wheel closure required")
    require(0 < len(value["sdk_build"]["wheels"]) <= 256, "offline SDK build-tool closure required")
    for path in ("native-candidate/Cargo.toml", "native-candidate/Cargo.lock"):
        require(value["source_pins"][path] == digest(ROOT / path), "selected native source pins differ")
    require(value["expected_package_ids"] and value["expected_features"]
            and value["expected_resolve"] and value["native_family_packages"], "exact actual native graph selection required")
    return value, revision, tree


class Recorder:
    def __init__(self, work):
        self.work = work
        self.records = work / "records"
        self.records.mkdir()

    def run(self, name, argv, *, cwd=ROOT, env=None, seconds=600):
        argv = [str(item) for item in argv]
        selected_env = {**os.environ, **(env or {})}
        log = self.records / (name + ".log")
        started = time.time()
        expired = False
        code = None
        with log.open("xb") as stream:
            process = subprocess.Popen(argv, cwd=cwd, env=selected_env,
                                       stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                expired = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    code = process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    code = process.wait()
        record_env = {key: selected_env[key] for key in (
            "RUSTUP_TOOLCHAIN", "XDG_CACHE_HOME", "RUST_LANE_ID", "CARGO_INCREMENTAL",
            "CARGO_TERM_COLOR", "CARGO_BUILD_JOBS", "MEERKAT_CONNECT_RESOURCES_SHA256", "TMPDIR")
            if key in selected_env}
        record = {"argv": argv, "cwd": str(cwd), "env": record_env, "exit_code": code,
                  "timed_out": expired, "elapsed_seconds": time.time() - started, "log": binding(log)}
        write_new(self.records / (name + ".json"), record)
        require(code == 0 and not expired, "command did not succeed: " + name)
        return record, log


def download(path, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    # GitHub release downloads redirect to its release-asset CDN. The original
    # URL and all resulting bytes remain explicitly selected; no API credentials.
    with urllib.request.urlopen(row["url"], timeout=60) as response, path.open("xb") as stream:
        size = 0
        while block := response.read(1024 * 1024):
            size += len(block)
            require(size <= row["size"], "public input exceeds selected size")
            stream.write(block)
    require(size == row["size"] and digest(path) == row["sha256"], "public input bytes differ")
    path.chmod(0o644)


def provenance(value):
    """Refuse historical private locators; do not rewrite producer bytes."""
    if isinstance(value, dict):
        for item in value.values():
            provenance(item)
    elif isinstance(value, list):
        for item in value:
            provenance(item)
    elif isinstance(value, str):
        require(not re.search(r"/Users/|/private/|/var/folders/|/home/(?!runner(?:/|$))[^/]+/", value),
                "private input provenance requires fresh owner-produced CI artifacts")
        for item in re.findall(r"(?:^|[=\s\"'])/(?:tmp|var/tmp|srv|opt)/[^\s\"']*", value):
            allowed = (str(ROOT), os.environ.get("RUNNER_TEMP", ""), "/opt/hostedtoolcache/")
            require(any(prefix and item.lstrip("= \t\"'").startswith(prefix) for prefix in allowed),
                    "foreign absolute producer locator requires fresh CI provenance")


def inspect_prebuilt(path):
    if path.name.endswith((".tar.gz", ".tar.zst")):
        # Only gzip libraries carry nested Connect provenance; zstd Python
        # runtime archives are verified by the existing resource packager.
        if path.name.endswith(".tar.zst"):
            return
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                if member.isfile() and (Path(member.name).name in {
                        "CONTENTS.json", "source-manifest.json", "build-record.json",
                        "resource-build-record.json", "direct_url.json"}
                        or member.name.endswith(".json")
                        or ("provenance" in PurePosixPath(member.name).parts
                            and Path(member.name).suffix in {
                                ".log", ".txt", ".stdout", ".stderr", ".sha256",
                                ".py", ".sh", ".toml", ".yml", ".yaml", ".md"})):
                    require(member.size <= 32 * 1024**2, "embedded provenance exceeds bound")
                    raw = archive.extractfile(member).read()
                    if member.name.endswith(".json"):
                        provenance(json.loads(raw, object_pairs_hook=unique))
                    else:
                        provenance(raw.decode("utf-8"))
    elif path.suffix == ".json":
        provenance(read_json(path))
    elif path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                if not item.is_dir() and ".dist-info/" in item.filename:
                    require(item.file_size <= 32 * 1024**2, "wheel provenance exceeds bound")
                    raw = archive.read(item)
                    provenance(json.loads(raw, object_pairs_hook=unique) if item.filename.endswith(".json")
                               else raw.decode("utf-8"))


def wheel_expectation(path, selected, source):
    with zipfile.ZipFile(path) as wheel:
        names = [item.filename for item in wheel.infolist() if not item.is_dir()]
        require(len(names) == len(set(names)) and len(names) <= 4096, "invalid wheel inventory")
        for name in names:
            relative(name)
        roots = {name.split("/", 1)[0] for name in names if ".dist-info/" in name}
        require(len(roots) == 1, "one wheel metadata owner required")
        prefix = next(iter(roots)) + "/"
        metadata = email.parser.BytesParser().parsebytes(wheel.read(prefix + "METADATA"))
        require(metadata["Name"] == selected["distribution"] and metadata["Version"] == selected["version"]
                and VERSION.fullmatch(selected["version"]), "wheel metadata differs from selection")
        payload = sorted(name for name in names if not name.startswith(prefix))
        require(set(payload) == set(selected["source_files"]), "complete wheel-to-source map required")
        for name in payload:
            source_name = relative(selected["source_files"][name])
            require(wheel.read(name) == (source / source_name).read_bytes(), "wheel payload differs from selected source")
        def rows(items, strip=""):
            return [[name.removeprefix(strip), hashlib.sha256(wheel.read(name)).hexdigest(), len(wheel.read(name))]
                    for name in sorted(items)]
        return {"distribution": selected["distribution"], "version": selected["version"],
                "sha256": digest(path), "size": path.stat().st_size,
                "source_payload": rows(payload),
                "metadata": rows([name for name in names if name.startswith(prefix)], prefix)}


def copy_exact(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o644)
    require(digest(destination) == digest(source), "retained file differs")


def archive_tree(directory, destination):
    with destination.open("xb") as stream, gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in [directory, *sorted(directory.rglob("*"))]:
                if path.is_symlink():
                    require(not Path(os.readlink(path)).is_absolute()
                            and path.resolve(strict=True).is_relative_to(directory),
                            "candidate symlink escapes its physical closure")
                info = archive.gettarinfo(str(path), arcname=path.relative_to(directory.parent).as_posix())
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                if path.is_file() and not path.is_symlink():
                    with path.open("rb") as payload:
                        archive.addfile(info, payload)
                else:
                    archive.addfile(info)


def build():
    value, revision, tree = preflight()
    work = Path(os.environ["RUNNER_TEMP"]) / "connect-candidate"
    require(not work.exists() and not (ROOT / "dist").exists(), "fresh output roots required")
    work.mkdir()
    (work / "tmp").mkdir()
    os.environ["TMPDIR"] = str(work / "tmp")
    record = Recorder(work)
    inputs = work / "inputs"
    artifacts = work / "artifacts"
    artifacts.mkdir()
    copy_exact(INPUTS, work / "inputs-selection.json")
    for name, row in value["files"].items():
        download(inputs / name, row)
        inspect_prebuilt(inputs / name)
    # Fetch the actual immutable published release tags into fresh checkouts.
    # A tag/source mismatch refuses; no previous checkout or native cache is used.
    releases = {}
    for domain in ("core", "meta"):
        selected = value["native_release"][domain]
        checkout = work / (domain + "-source")
        record.run(domain + "-clone", ["git", "clone", "--no-checkout", "--filter=blob:none", "--single-branch",
            "--branch", selected["tag"], "https://github.com/" + selected["repository"] + ".git", checkout])
        _, identity_log = record.run(domain + "-identity", ["git", "rev-parse", "HEAD"], cwd=checkout)
        require(identity_log.read_text().strip() == selected["source_sha"], "published native tag points elsewhere")
        record.run(domain + "-checkout", ["git", "checkout", "--detach", selected["source_sha"]], cwd=checkout)
        releases[domain] = checkout
    for name, expected in value["forge_reader_source_pins"].items():
        path = releases["meta"] / name
        require(path.is_file() and not path.is_symlink() and digest(path) == expected,
                "published Meta release lacks the selected actual Forge reader")
    # --no-index alone does not forbid direct URLs or included requirements.
    # The selected owner's existing reader validates the exact single-hash
    # grammar and each original wheel/RECORD before either pip installation.
    for batch_name in ("sdk_build", "dependencies"):
        batch = value[batch_name]
        batch_selection = work / (batch_name + "-selection.json")
        write_new(batch_selection, {"requirements": binding(inputs / batch["requirements"]),
            "wheels": [binding(inputs / name) for name in batch["wheels"]]})
        record.run(batch_name + "-read", [sys.executable, "-I", "-c",
            "import json,sys; from pathlib import Path; "
            "sys.path.insert(0,sys.argv[1]); "
            "from launchkit.runtime_candidates import ArtifactFile; "
            "from launchkit.templates.install_candidate import _read_selected_dependency_wheels; "
            "selected=json.loads(Path(sys.argv[2]).read_text()); "
            "pin=lambda row: ArtifactFile(Path(row['path']),row['size'],row['sha256']); "
            "pending=_read_selected_dependency_wheels(pin(selected['requirements']),"
            "tuple(pin(row) for row in selected['wheels'])); "
            "print(json.dumps({'status':'exact_batch_verified','wheels':len(pending)}))",
            releases["meta"] / "installer", batch_selection], seconds=300)
    # Build the selected Connect SDK through its existing PEP 517 backend. The
    # scratch copy avoids source-checkout mutations; no prior Connect publication
    # is needed. The frontend/backend dependency wheels are explicit offline inputs.
    sdk_source = work / "sdk-source"
    shutil.copytree(ROOT / "sdk/python", sdk_source, symlinks=True)
    sdk_venv = Path(os.environ["RUNNER_TEMP"]) / "connect-sdk-build-venv"
    require(not sdk_venv.exists(), "fresh SDK build environment required")
    record.run("sdk-build-venv", [sys.executable, "-m", "venv", sdk_venv])
    sdk_python = sdk_venv / "bin/python"
    sdk_tools = work / "sdk-build-wheelhouse"
    sdk_tools.mkdir()
    for name in value["sdk_build"]["wheels"]:
        copy_exact(inputs / name, sdk_tools / Path(name).name)
    record.run("sdk-build-tools", [sdk_python, "-m", "pip", "install", "--no-index", "--no-deps", "--require-hashes",
        "--find-links", sdk_tools, "-r", inputs / value["sdk_build"]["requirements"]])
    record.run("sdk-build-inventory", [sdk_python, "-m", "pip", "list", "--format=json"])
    sdk_output = work / "sdk-built"
    sdk_output.mkdir()
    record.run("sdk-wheel", [sdk_python, "-m", "build", "--wheel", "--no-isolation",
        "--outdir", sdk_output, sdk_source], seconds=600)
    wheels = list(sdk_output.glob("*.whl"))
    require(len(wheels) == 1 and list(sdk_output.iterdir()) == wheels, "one original SDK wheel required")
    sdk_wheels = {"toolkit": wheels[0], "meta": inputs / value["sdks"]["meta"]["wheel"]}
    expectations = {name: wheel_expectation(sdk_wheels[name],
        value["sdks"][name], ROOT if name == "toolkit" else releases["meta"]) for name in ("meta", "toolkit")}
    inspect_prebuilt(sdk_wheels["toolkit"])
    write_new(artifacts / "SDK-BYTE-EXPECTATIONS.json", expectations)
    record.run("rust-version", ["rustc", "+1.97.0", "--version", "--verbose"])
    record.run("cargo-version", ["cargo", "+1.97.0", "--version", "--verbose"])
    record.run("python-version", [sys.executable, "--version"])
    record.run("system-packages", ["dpkg-query", "-W"])
    record.run("system", ["uname", "-a"])
    resource = value["resources"]
    upstream = work / "upstream"
    starter = work / "starter"
    upstream.mkdir()
    for name in resource["upstream"]:
        copy_exact(inputs / name, upstream / Path(name).name)
    # Project only the actual selected library bytes into the existing starter
    # manifest shape. This is a candidate input selector, not a release receipt.
    library = inputs / resource["library"]
    starter_manifest = work / "starter-library-selection.json"
    write_new(starter_manifest, {"schema_version": 1, "status": "candidate_input_not_published",
        "assets": [{"upload_name": library.name, "bytes": library.stat().st_size, "sha256": digest(library)}]})
    record.run("starter-export", [sys.executable, ROOT / "scripts/export-setup-starter.py",
        "--destination", starter, "--manifest", starter_manifest, "--manifest-sha256", digest(starter_manifest)])
    args = [sys.executable, ROOT / "scripts/package-connect-resources.py",
        "--destination", work / "resources", "--upstream", upstream, "--zstd", shutil.which("zstd"),
        "--target", TARGET, "--starter", starter,
        "--release-manifest-sha256", digest(starter / "release-manifest.json")]
    for key, option in (("library", "library"), ("acquisition_node", "acquisition-node"), ("npm", "npm")):
        row = value["files"][resource[key]]
        locator = option + "-archive" if key in ("acquisition_node", "npm") else option
        args += ["--" + locator, inputs / resource[key], "--" + option + "-sha256", row["sha256"],
                 "--" + option + "-bytes", str(row["size"])]
    for key, option in (("node_prebuilt_policy", "node-prebuilt-policy"), ("node_build_profile", "node-build-profile")):
        if resource.get(key):
            args += ["--" + option, inputs / resource[key], "--" + option + "-sha256",
                     value["files"][resource[key]]["sha256"]]
    record.run("resources", args, seconds=900)
    resource_record = work / "resources/build.json"
    resource_value = read_json(resource_record)
    provenance(resource_value)
    wrapper = ROOT / "scripts/repo-cargo"
    manifest = ROOT / "native-candidate/Cargo.toml"
    _, metadata_log = record.run("metadata", [wrapper, "+1.97.0", "metadata", "--locked", "--format-version", "1",
        "--manifest-path", manifest, "--features", "console,toolkit-mobkit/native-host"], seconds=900)
    # Cargo may print progress before JSON; only the single actual metadata row counts.
    metadata_rows = [json.loads(line) for line in metadata_log.read_text().splitlines() if line.startswith('{')]
    require(len(metadata_rows) == 1, "one actual Cargo metadata result required")
    metadata = metadata_rows[0]
    connect_packages = [package for package in metadata["packages"] if package["name"] == "meerkat-connect"]
    require(len(connect_packages) == 1 and connect_packages[0]["version"] == value["connect_version"]
            and Path(connect_packages[0]["manifest_path"]) == ROOT / "crates/meerkat-connect/Cargo.toml",
            "actual Connect package does not match selected source/version")
    def normalized(identity):
        # Only the selected workspace path is made portable for comparison;
        # all public registry/Git identities remain exact. Raw metadata is kept.
        return identity.replace("path+file://" + str(ROOT) + "/", "path+workspace:///").replace(
            "path+file://" + str(ROOT) + "#", "path+workspace:///#")
    require(sorted(normalized(package["id"]) for package in metadata["packages"])
            == sorted(value["expected_package_ids"]), "actual package graph differs")
    features = {normalized(node["id"]): sorted(node["features"]) for node in metadata["resolve"]["nodes"]}
    require(features == value["expected_features"], "actual feature graph differs")
    resolve = []
    for node in metadata["resolve"]["nodes"]:
        deps = [{"name": dep["name"], "pkg": normalized(dep["pkg"]),
                 "dep_kinds": sorted([{"kind": kind["kind"] or "normal", "target": kind["target"] or ""}
                                      for kind in dep["dep_kinds"]], key=lambda item: (item["kind"], item["target"]))}
                for dep in node["deps"]]
        resolve.append({"id": normalized(node["id"]), "dependencies": sorted(normalized(item) for item in node["dependencies"]),
                        "deps": sorted(deps, key=lambda item: (item["name"], item["pkg"]))})
    normalized_resolve = {"root": normalized(metadata["resolve"]["root"]) if metadata["resolve"]["root"] else "",
                          "nodes": sorted(resolve, key=lambda item: item["id"])}
    require(normalized_resolve == value["expected_resolve"],
            "actual dependency edges or dependency kinds differ")
    families = []
    for package in metadata["packages"]:
        name = package["name"]
        if name in {"meerkat-connect", "meerkat-toolkit"}:
            require(package["source"] is None and package["id"] in metadata["workspace_members"]
                    and Path(package["manifest_path"]) == ROOT / "crates" / name / "Cargo.toml",
                    "Connect-owned package is not the exact selected workspace member")
        elif name == "meerkat" or name.startswith("meerkat-"):
            families.append(package)
    require({package["name"] for package in families} == set(value["native_family_packages"])
            and all(package["version"] == "0.9.4" for package in families),
            "native family is not the complete selected published 0.9.4 graph")
    for package in families:
        source = package["source"]
        require(isinstance(source, str), "path-sourced native family package is not a published release")
        if source == "registry+https://github.com/rust-lang/crates.io-index":
            continue  # Cargo verifies the exact selected lock's registry checksum.
        domain = "meta" if package["name"] == "meerkat-meta" else "core"
        release = value["native_release"][domain]
        require(source.startswith("git+https://github.com/" + release["repository"] + ".git?")
                and source.endswith("#" + release["source_sha"]),
                "native Git source is not the selected published release commit")
    # Exact IDs distinguish registry versions from Git commit sources; the
    # registry checksums remain pinned by the unchanged selected lock bytes.
    source_files = []
    tracked = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"]).decode().split('\0')
    for name in filter(None, tracked):
        path = ROOT / name
        require(not path.is_symlink(), "source census requires explicit symlink support before selection")
        source_files.append({"path": name, "sha256": digest(path), "size": path.stat().st_size,
                             "mode": oct(stat.S_IMODE(path.stat().st_mode))})
    source_manifest = artifacts / "source-manifest.json"
    write_new(source_manifest, {"schema_version": 1, "repository": os.environ["GITHUB_REPOSITORY"],
        "revision": revision, "tree": tree, "files": source_files,
        "native_release": value["native_release"], "metadata": binding(metadata_log),
        "input_selection": binding(work / "inputs-selection.json")})
    bound_env = {"MEERKAT_CONNECT_RESOURCES_SHA256": resource_value["resources_sha256"]}
    cargo, cargo_log = record.run("native-build", [wrapper, "+1.97.0", "build", "--locked", "--release",
        "--manifest-path", manifest, "-p", "meerkat-connect", "--features", "console,toolkit-mobkit/native-host",
        "--bin", "toolkit_gateway", "--message-format=json-render-diagnostics"], env=bound_env, seconds=5400)
    emitted = [json.loads(line) for line in cargo_log.read_text().splitlines() if line.startswith('{')]
    binaries = [Path(row["executable"]) for row in emitted if row.get("reason") == "compiler-artifact"
                and row.get("target", {}).get("name") == "toolkit_gateway" and row.get("executable")]
    require(len(binaries) == 1, "one actual emitted gateway executable required")
    binary = work / "binary/toolkit_gateway"
    copy_exact(binaries[0], binary)
    binary.chmod(0o755)
    native_record = work / "build-record.json"
    write_new(native_record, {"schema_version": 1, "target": TARGET, "binary_kind": "toolkit_gateway",
        "resources_sha256": resource_value["resources_sha256"], "binary": binding(binary), "cargo": cargo,
        "source_manifest": binding(source_manifest), "resource_build_record_sha256": digest(resource_record)})
    assembly = [sys.executable, ROOT / "scripts/assemble-connect-product.py", "--binary", binary,
        "--binary-sha256", digest(binary), "--build-record", native_record,
        "--resource-build-record", resource_record, "--resource-build-record-sha256", digest(resource_record),
        "--binary-kind", "toolkit_gateway", "--target", TARGET, "--release-version", value["connect_version"]]
    record.run("stage", [*assembly, "--stage-only", "--destination", work / "stage"], seconds=600)
    # Install the original selected Meta wheel and the just-built Connect wheel.
    # There is no network dependency resolution or second SDK build here.
    venv = Path(os.environ["RUNNER_TEMP"]) / "connect-verifier-venv"
    require(not venv.exists(), "fresh verifier environment required")
    record.run("venv", [sys.executable, "-m", "venv", venv])
    python = venv / "bin/python"
    dependency = value["dependencies"]
    wheelhouse = work / "wheelhouse"
    wheelhouse.mkdir()
    for name in dependency["wheels"]:
        copy_exact(inputs / name, wheelhouse / Path(name).name)
    record.run("dependencies", [python, "-m", "pip", "install", "--no-index", "--no-deps", "--require-hashes",
        "--find-links", wheelhouse, "-r", inputs / dependency["requirements"]])
    record.run("sdks", [python, "-m", "pip", "install", "--no-index", "--no-deps",
        sdk_wheels["meta"], sdk_wheels["toolkit"]])
    _, site_log = record.run("site", [python, "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"])
    site = Path(site_log.read_text().strip())
    staged = work / "stage/staging.json"
    record.run("installed-product", [python, "-I", ROOT / "scripts/verify_native_gateway_subprocess.py",
        "--toolkit-gateway", work / ("stage/meerkat-connect-" + TARGET + "/bin/toolkit_gateway"),
        "--toolkit-python", site, "--meta-python", site, "--case", "installed-product",
        "--installed-staging", staged, "--installed-staging-sha256", digest(staged),
        "--output", work / "verification"], seconds=900)
    verification = work / "verification/manifest.json"
    report = read_json(verification)
    require(report["status"] == "passed", "actual installed verification failed")
    record.run("assemble", [*assembly, "--destination", work / "assembled",
        "--gateway-verification", verification, "--gateway-verification-sha256", digest(verification)], seconds=600)
    final = read_json(work / "assembled/assembly.json")
    require(final["scope"] == SCOPE and final["release_version"] == value["connect_version"],
            "final assembly scope or version differs")
    for name in ("assembly.json", "build-record.json", "resource-build-record.json", "gateway-verification.json", final["archive"], final["archive"] + ".sha256"):
        copy_exact(work / "assembled" / name, artifacts / name)
    for name in ("meta", "toolkit"):
        copy_exact(sdk_wheels[name], artifacts / sdk_wheels[name].name)
    for name in dependency["wheels"]:
        copy_exact(inputs / name, artifacts / "dependencies" / Path(name).name)
    copy_exact(inputs / dependency["requirements"], artifacts / "dependency-requirements.txt")
    catalog = Path(report["cases"][0]["model_catalog"]["path"])
    require(digest(catalog) == report["cases"][0]["model_catalog"]["sha256"], "actual catalog changed")
    copy_exact(catalog, artifacts / "model-catalog.json")
    # Exact public reader shape. The producer's absolute locators stay untouched;
    # Forge owns only their later physical relocation, not record rewriting.
    selection = {"format": "forge-meta-toolkit-runtime-selection-v1", "artifact_root": str(artifacts), "target": TARGET,
        "assembly": binding(artifacts / "assembly.json"), "source_manifest": binding(source_manifest),
        "meta_wheel": binding(artifacts / sdk_wheels["meta"].name),
        "toolkit_wheel": binding(artifacts / sdk_wheels["toolkit"].name),
        "dependency_requirements": binding(artifacts / "dependency-requirements.txt"),
        "dependency_wheels": [binding(artifacts / "dependencies" / Path(name).name) for name in dependency["wheels"]],
        "model_catalog": binding(artifacts / "model-catalog.json"), **expectations}
    write_new(artifacts / "RUNTIME-SELECTION.json", selection)
    # Use the selected release's real reader, not a Connect-side reimplementation
    # of the installer acceptance contract. An absent/incompatible reader refuses.
    record.run("forge-reader", [python, "-I", "-c",
        "import json,sys; from pathlib import Path; "
        "sys.path.insert(0,sys.argv[1]); "
        "from launchkit.runtime_selection import parse_candidate_selection; "
        "from launchkit.runtime_candidates import read_meta_toolkit_artifacts; "
        "target=parse_candidate_selection(json.loads(Path(sys.argv[2]).read_text())); "
        "observed=read_meta_toolkit_artifacts(target); "
        "assert observed.origin=='installed-gateway-assembly'; "
        "print(json.dumps({'origin':observed.origin,'status':'verified','published':False}))",
        releases["meta"] / "installer", artifacts / "RUNTIME-SELECTION.json"], seconds=300)
    require(source_state() == (revision, tree), "selected source changed during production")
    for path in ("native-candidate/Cargo.toml", "native-candidate/Cargo.lock"):
        require(digest(ROOT / path) == value["source_pins"][path], "Cargo changed selected source")
    # Retain raw records and input provenance, but not tool caches, checkouts or
    # the installed venv. The original source/SDK identities remain in records.
    closure = Path(os.environ["RUNNER_TEMP"]) / "connect-export"
    closure.mkdir()
    for name in ("artifacts", "records", "inputs", "upstream", "starter", "resources", "stage", "verification", "binary", "tmp", "sdk-built"):
        shutil.copytree(work / name, closure / name, symlinks=True)
    for name in ("inputs-selection.json", "build-record.json", "starter-library-selection.json",
                 "sdk_build-selection.json", "dependencies-selection.json"):
        copy_exact(work / name, closure / name)
    rows = []
    for path in sorted(closure.rglob("*")):
        if path.is_symlink():
            raw = os.readlink(path).encode()
            rows.append({"path": path.relative_to(closure).as_posix(), "kind": "symlink",
                         "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        elif path.is_file() and not path.is_symlink():
            if path.suffix == ".json":
                provenance(read_json(path))
            elif path.suffix in {".log", ".txt", ".sha256"} or path.name == "gateway.stderr":
                provenance(path.read_text(encoding="utf-8", errors="strict"))
            rows.append({"path": path.relative_to(closure).as_posix(), "size": path.stat().st_size, "sha256": digest(path)})
    write_new(closure / "CONTENTS.json", {"schema_version": 1, "files": rows})
    dist = ROOT / "dist"
    dist.mkdir()
    archive = dist / "connect-linux-candidate.tar.gz"
    archive_tree(closure, archive)
    require(0 < archive.stat().st_size <= MAX_FILE, "candidate wrapper exceeds Forge public input/archive limit")
    write_new(dist / "connect-candidate.json", {"schema_version": 1, "kind": "connect-installed-candidate",
        "repository": os.environ["GITHUB_REPOSITORY"], "source_sha": revision, "source_tree": tree,
        "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "target": TARGET, "scope": SCOPE,
        "connect_version": value["connect_version"], "native_release": value["native_release"],
        "inputs_sha256": digest(INPUTS), "archive": {"name": archive.name, "size": archive.stat().st_size, "sha256": digest(archive)},
        "runtime_selection_sha256": digest(artifacts / "RUNTIME-SELECTION.json"), "publication": "not_performed"})


def fetch_built():
    preflight()
    identifier = os.environ.get("CONNECT_ARTIFACT_ID", "")
    expected = os.environ.get("CONNECT_ARTIFACT_DIGEST", "").removeprefix("sha256:")
    require(identifier.isdigit() and HEX.fullmatch(expected), "exact build artifact ID and digest required")
    endpoint = "repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/artifacts/" + identifier
    metadata = json.loads(subprocess.check_output(["gh", "api", endpoint]))
    expected_name = "connect-linux-build-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    require(metadata["name"] == expected_name and str(metadata["workflow_run"]["id"]) == os.environ["GITHUB_RUN_ID"]
            and metadata["workflow_run"]["head_sha"] == os.environ["CONNECT_SOURCE_SHA"]
            and not metadata["expired"] and metadata["digest"].removeprefix("sha256:") == expected,
            "artifact run, attempt, source or digest differs")
    archive = Path(os.environ["RUNNER_TEMP"]) / "connect-built.zip"
    with archive.open("xb") as stream:
        subprocess.run(["gh", "api", endpoint + "/zip"], stdout=stream, check=True)
    require(digest(archive) == expected, "downloaded artifact digest differs")
    dist = ROOT / "dist"
    dist.mkdir()
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        require(len(entries) == 2 and {entry.filename for entry in entries}
                == {"connect-linux-candidate.tar.gz", "connect-candidate.json"}, "unexpected attestation subject set")
        for entry in entries:
            require(0 < entry.file_size <= MAX_FILE and not stat.S_ISLNK(entry.external_attr >> 16),
                    "invalid attestation subject")
            with zipped.open(entry) as source, (dist / entry.filename).open("xb") as destination:
                shutil.copyfileobj(source, destination)
    manifest = read_json(dist / "connect-candidate.json")
    require(manifest["source_sha"] == os.environ["CONNECT_SOURCE_SHA"]
            and manifest["workflow_sha"] == os.environ["GITHUB_WORKFLOW_SHA"]
            and manifest["run_id"] == os.environ["GITHUB_RUN_ID"]
            and manifest["run_attempt"] == os.environ["GITHUB_RUN_ATTEMPT"]
            and manifest["inputs_sha256"] == os.environ["CONNECT_INPUTS_SHA256"], "candidate binding differs")
    payload = dist / "connect-linux-candidate.tar.gz"
    require(manifest["archive"] == {"name": payload.name, "size": payload.stat().st_size, "sha256": digest(payload)},
            "candidate closure differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "build", "fetch-built"))
    command = parser.parse_args().command
    if command == "preflight":
        preflight()
    elif command == "build":
        build()
    else:
        fetch_built()


if __name__ == "__main__":
    main()
