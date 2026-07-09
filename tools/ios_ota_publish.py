#!/usr/bin/env python3
"""Prepare an iOS OTA install page, optional OSS upload, and HTTPS serving."""

from __future__ import annotations

import argparse
import base64
import email.utils
import functools
import hashlib
import hmac
import html
import http.client
import ipaddress
import mimetypes
import os
import plistlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


DEFAULT_PORT = 8443


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def detect_ipa(root: Path, ipa_dir: str | None = None) -> Path:
    ipas = list(root.glob("*.ipa"))
    if ipa_dir:
        ipa_dir_path = root / ipa_dir
        if ipa_dir_path.exists():
            ipas.extend(ipa_dir_path.glob("*.ipa"))
    ipas = sorted(set(ipas))
    if len(ipas) == 1:
        return ipas[0]
    if not ipas:
        locations = [str(root)]
        if ipa_dir:
            locations.append(str(root / ipa_dir))
        fail("no .ipa file found in " + " or ".join(locations) + "; pass --ipa")
    fail("multiple .ipa files found; keep only one IPA or pass --ipa")


def load_ipa_metadata(ipa_path: Path) -> dict[str, str]:
    with zipfile.ZipFile(ipa_path) as ipa:
        info_name = next(
            (
                name
                for name in ipa.namelist()
                if name.startswith("Payload/")
                and name.endswith(".app/Info.plist")
                and name.count("/") == 2
            ),
            None,
        )
        if not info_name:
            fail(f"could not find Payload/*.app/Info.plist in {ipa_path}")
        info = plistlib.loads(ipa.read(info_name))

    bundle_id = info.get("CFBundleIdentifier")
    version = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
    build = info.get("CFBundleVersion") or version
    title = (
        info.get("CFBundleDisplayName")
        or info.get("CFBundleName")
        or Path(info_name).parts[1].replace(".app", "")
    )
    if not bundle_id or not version:
        fail("IPA Info.plist is missing CFBundleIdentifier or version")

    return {
        "bundle_id": str(bundle_id),
        "version": str(version),
        "build": str(build),
        "title": str(title),
    }


def extract_app_icon(ipa_path: Path, output_path: Path) -> Path | None:
    with zipfile.ZipFile(ipa_path) as ipa:
        info_name = next(
            (
                name
                for name in ipa.namelist()
                if name.startswith("Payload/")
                and name.endswith(".app/Info.plist")
                and name.count("/") == 2
            ),
            None,
        )
        if not info_name:
            return None
        info = plistlib.loads(ipa.read(info_name))
        app_prefix = info_name.rsplit("/", 1)[0] + "/"
        icon_basenames: list[str] = []

        def add_icon_files(container_key: str) -> None:
            primary = (
                info.get(container_key, {})
                .get("CFBundlePrimaryIcon", {})
                .get("CFBundleIconFiles", [])
            )
            for icon_name in primary:
                if icon_name not in icon_basenames:
                    icon_basenames.append(str(icon_name))

        add_icon_files("CFBundleIcons")
        add_icon_files("CFBundleIcons~ipad")

        candidates: list[str] = []
        for basename in icon_basenames:
            if basename.endswith(".png"):
                candidates.append(app_prefix + basename)
            else:
                candidates.extend(
                    [
                        app_prefix + basename + "@3x.png",
                        app_prefix + basename + "@2x.png",
                        app_prefix + basename + ".png",
                        app_prefix + basename + "@2x~ipad.png",
                        app_prefix + basename + "~ipad.png",
                    ]
                )
        candidates.extend(
            name
            for name in ipa.namelist()
            if name.startswith(app_prefix)
            and name.lower().endswith(".png")
            and "appicon" in Path(name).name.lower()
        )

        for candidate in dict.fromkeys(candidates):
            try:
                data = ipa.read(candidate)
            except KeyError:
                continue
            output_path.write_bytes(data)
            return output_path
    return None


def make_full_size_icon(icon_path: Path | None, output_path: Path) -> Path | None:
    if not icon_path:
        return None
    sips = shutil.which("sips")
    if sips:
        result = subprocess.run(
            [sips, "-z", "512", "512", str(icon_path), "--out", str(output_path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0 and output_path.exists():
            return output_path
    shutil.copyfile(icon_path, output_path)
    return output_path


def guess_lan_host() -> str:
    for interface in ("en0", "en1", "bridge100"):
        try:
            result = subprocess.run(
                ["ipconfig", "getifaddr", interface],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            candidate = result.stdout.strip()
            if candidate:
                return candidate
        except OSError:
            break

    try:
        result = subprocess.run(
            ["ifconfig"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        blocks = re.split(r"\n(?=\S)", result.stdout)
        preferred: list[str] = []
        fallback: list[str] = []
        for block in blocks:
            interface_name = block.split(":", 1)[0]
            if interface_name.startswith(("lo", "utun", "awdl", "llw")):
                continue
            for match in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\b", block):
                candidate = match.group(1)
                if candidate.startswith(("127.", "169.254.")):
                    continue
                if "status: active" in block:
                    preferred.append(candidate)
                else:
                    fallback.append(candidate)
        if preferred:
            return preferred[0]
        if fallback:
            return fallback[0]
    except OSError:
        pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        sock.close()


def normalize_url_base(base_url: str) -> str:
    base_url = base_url.strip()
    if not base_url:
        fail("empty base URL")
    return base_url.rstrip("/")


def join_url(base_url: str, *parts: str) -> str:
    base = normalize_url_base(base_url)
    quoted_parts = [
        urllib.parse.quote(str(part).strip("/"), safe="/")
        for part in parts
        if str(part).strip("/")
    ]
    return "/".join([base, *quoted_parts])


def url_path_for(root: Path, file_path: Path) -> str:
    try:
        relative = file_path.resolve().relative_to(root.resolve())
        return relative.as_posix()
    except ValueError:
        return file_path.name


def make_manifest(
    manifest_path: Path,
    ipa_url: str,
    metadata: dict[str, str],
    display_image_url: str | None = None,
    full_size_image_url: str | None = None,
) -> None:
    assets = [
        {
            "kind": "software-package",
            "url": ipa_url,
        }
    ]
    if display_image_url:
        assets.append(
            {
                "kind": "display-image",
                "needs-shine": False,
                "url": display_image_url,
            }
        )
    if full_size_image_url:
        assets.append(
            {
                "kind": "full-size-image",
                "needs-shine": False,
                "url": full_size_image_url,
            }
        )

    manifest = {
        "items": [
            {
                "assets": assets,
                "metadata": {
                    "bundle-identifier": metadata["bundle_id"],
                    "bundle-version": metadata["build"],
                    "kind": "software",
                    "title": metadata["title"],
                },
            }
        ]
    }
    with manifest_path.open("wb") as fp:
        plistlib.dump(manifest, fp, sort_keys=False)


def make_install_html(
    html_path: Path,
    manifest_url: str,
    ipa_url: str,
    metadata: dict[str, str],
    mode: str,
    cert_url: str | None,
    cert_profile_url: str | None,
) -> str:
    install_href = "itms-services://?" + urllib.parse.urlencode(
        {"action": "download-manifest", "url": manifest_url}
    )
    title = html.escape(metadata["title"])
    bundle_id = html.escape(metadata["bundle_id"])
    version = html.escape(metadata["version"])
    build = html.escape(metadata["build"])
    mode_label = html.escape(mode)
    manifest_text = html.escape(manifest_url)
    ipa_text = html.escape(ipa_url)
    install_href_attr = html.escape(install_href, quote=True)
    cert_block = ""
    if cert_url or cert_profile_url:
        cert_text = html.escape(cert_url or "")
        cert_href = html.escape(cert_url or "", quote=True)
        profile_text = html.escape(cert_profile_url or "")
        profile_href = html.escape(cert_profile_url or "", quote=True)
        profile_link = (
            f'<a class="secondary" href="{profile_href}">Install certificate profile</a>'
            if cert_profile_url
            else ""
        )
        cert_link = (
            f'<a class="secondary" href="{cert_href}">Download certificate</a>'
            if cert_url
            else ""
        )
        cert_code = cert_text
        if cert_profile_url:
            cert_code = profile_text + ("\n" + cert_text if cert_text else "")
        cert_block = f"""
        <section>
          <h2>Local Certificate</h2>
          <p>For local HTTPS installs, trust the certificate on the iPhone before tapping Install.</p>
          {profile_link}
          {cert_link}
          <code>{cert_code}</code>
        </section>"""

    html_path.write_text(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Install {title}</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1f2933;
      --muted: #64748b;
      --line: #d7dde5;
      --accent: #126f5a;
      --accent-strong: #0d5c49;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #101418;
        --panel: #171d22;
        --text: #eef2f6;
        --muted: #9aa8b6;
        --line: #2f3a44;
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      display: grid;
      place-items: center;
      padding: 24px;
    }}
    main {{
      width: min(100%, 560px);
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 24px;
      box-shadow: 0 16px 42px rgba(15, 23, 42, 0.10);
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 28px;
      line-height: 1.2;
      letter-spacing: 0;
    }}
    h2 {{
      margin: 20px 0 8px;
      font-size: 14px;
      line-height: 1.35;
      letter-spacing: 0;
      color: var(--muted);
      text-transform: uppercase;
    }}
    p {{ margin: 0 0 16px; color: var(--muted); line-height: 1.5; }}
    .install {{
      display: block;
      width: 100%;
      text-align: center;
      text-decoration: none;
      color: #ffffff;
      background: var(--accent);
      border-radius: 8px;
      padding: 14px 18px;
      font-weight: 700;
      margin: 18px 0 8px;
    }}
    .install:active {{ background: var(--accent-strong); }}
    .secondary {{
      display: inline-block;
      color: var(--accent);
      font-weight: 700;
      text-decoration: none;
      margin-bottom: 10px;
    }}
    dl {{
      display: grid;
      grid-template-columns: 100px 1fr;
      gap: 10px 12px;
      margin: 18px 0 0;
      font-size: 14px;
    }}
    dt {{ color: var(--muted); }}
    dd {{ margin: 0; overflow-wrap: anywhere; }}
    code {{
      display: block;
      overflow-wrap: anywhere;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
      border-top: 1px solid var(--line);
      padding-top: 10px;
      margin-top: 10px;
    }}
  </style>
</head>
<body>
  <main>
    <h1>{title}</h1>
    <p>Version {version} ({build}) · {bundle_id}</p>
    <a class="install" href="{install_href_attr}">Install App</a>
    <dl>
      <dt>Mode</dt><dd>{mode_label}</dd>
      <dt>Manifest</dt><dd>{manifest_text}</dd>
      <dt>IPA</dt><dd>{ipa_text}</dd>
    </dl>
    {cert_block}
  </main>
</body>
</html>
""",
        encoding="utf-8",
    )
    return install_href


def sanitize_prefix(prefix: str) -> str:
    return "/".join(part for part in prefix.strip("/").split("/") if part)


def oss_endpoint_url(endpoint: str) -> urllib.parse.ParseResult:
    if "://" not in endpoint:
        endpoint = "https://" + endpoint
    parsed = urllib.parse.urlparse(endpoint)
    if not parsed.scheme or not parsed.netloc:
        fail(f"invalid OSS endpoint: {endpoint}")
    return parsed


def default_oss_public_base(bucket: str, endpoint: str) -> str:
    parsed = oss_endpoint_url(endpoint)
    return f"{parsed.scheme}://{bucket}.{parsed.netloc}"


def oss_object_url(public_base_url: str, object_key: str) -> str:
    return join_url(public_base_url, object_key)


def oss_put_file(
    file_path: Path,
    bucket: str,
    endpoint: str,
    object_key: str,
    access_key_id: str,
    access_key_secret: str,
    security_token: str | None = None,
    acl: str | None = None,
) -> None:
    parsed = oss_endpoint_url(endpoint)
    host = f"{bucket}.{parsed.netloc}"
    quoted_key = urllib.parse.quote(object_key, safe="/")
    url = f"{parsed.scheme}://{host}/{quoted_key}"
    data = file_path.read_bytes()
    content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    date = email.utils.formatdate(time.time(), usegmt=True)

    oss_headers: dict[str, str] = {}
    if security_token:
        oss_headers["x-oss-security-token"] = security_token
    if acl:
        oss_headers["x-oss-object-acl"] = acl

    canonicalized_headers = "".join(
        f"{key.lower()}:{value}\n" for key, value in sorted(oss_headers.items())
    )
    canonicalized_resource = f"/{bucket}/{object_key}"
    string_to_sign = (
        "PUT\n"
        "\n"
        f"{content_type}\n"
        f"{date}\n"
        f"{canonicalized_headers}"
        f"{canonicalized_resource}"
    )
    signature = base64.b64encode(
        hmac.new(
            access_key_secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha1,
        ).digest()
    ).decode("ascii")

    headers = {
        "Date": date,
        "Content-Type": content_type,
        "Content-Length": str(len(data)),
        "Authorization": f"OSS {access_key_id}:{signature}",
        **oss_headers,
    }
    request = urllib.request.Request(url, data=data, method="PUT", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status not in (200, 201):
                fail(f"OSS upload failed for {object_key}: HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        fail(f"OSS upload failed for {object_key}: HTTP {exc.code}\n{body}")
    except urllib.error.URLError as exc:
        fail(f"OSS upload failed for {object_key}: {exc}")


def ensure_https_cert(cert_dir: Path, lan_host: str) -> tuple[Path, Path, Path]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
    der_path = cert_dir / "server.cer"
    san_entries = ["DNS:localhost", "IP:127.0.0.1"]
    try:
        ipaddress.ip_address(lan_host)
        san_entries.append(f"IP:{lan_host}")
    except ValueError:
        san_entries.append(f"DNS:{lan_host}")
    san = ",".join(dict.fromkeys(san_entries))
    config_path = cert_dir / "openssl.cnf"

    if cert_path.exists() and key_path.exists() and der_path.exists():
        existing_config = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
        if f"CN = {lan_host}" in existing_config and f"subjectAltName = {san}" in existing_config:
            return cert_path, key_path, der_path
        for generated_file in (cert_path, key_path, der_path):
            generated_file.unlink(missing_ok=True)

    openssl = shutil.which("openssl")
    if not openssl:
        fail("openssl not found; install openssl or pass an existing certificate manually")

    config_path.write_text(
        f"""[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = {lan_host}

[v3_req]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyEncipherment, keyCertSign
extendedKeyUsage = serverAuth
subjectAltName = {san}
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "825",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-config",
            str(config_path),
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        fail("openssl certificate generation failed:\n" + result.stderr.strip())

    result = subprocess.run(
        [
            openssl,
            "x509",
            "-in",
            str(cert_path),
            "-outform",
            "der",
            "-out",
            str(der_path),
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        fail("openssl DER certificate export failed:\n" + result.stderr.strip())
    return cert_path, key_path, der_path


def make_certificate_mobileconfig(cert_der_path: Path, profile_path: Path, lan_host: str) -> Path:
    cert_payload_uuid = str(uuid.uuid4()).upper()
    profile_uuid = str(uuid.uuid4()).upper()
    payload = {
        "PayloadContent": [
            {
                "PayloadCertificateFileName": cert_der_path.name,
                "PayloadContent": cert_der_path.read_bytes(),
                "PayloadDescription": "Adds the local OTA HTTPS certificate.",
                "PayloadDisplayName": f"Local OTA HTTPS {lan_host}",
                "PayloadIdentifier": f"local.ota.cert.{cert_payload_uuid}",
                "PayloadType": "com.apple.security.root",
                "PayloadUUID": cert_payload_uuid,
                "PayloadVersion": 1,
            }
        ],
        "PayloadDescription": "Trust profile for local iOS OTA installation.",
        "PayloadDisplayName": "Local iOS OTA HTTPS Certificate",
        "PayloadIdentifier": f"local.ota.profile.{profile_uuid}",
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1,
    }
    with profile_path.open("wb") as fp:
        plistlib.dump(payload, fp, sort_keys=False)
    return profile_path


class OTAHTTPRequestHandler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".cer": "application/x-x509-ca-cert",
        ".ipa": "application/octet-stream",
        ".mobileconfig": "application/x-apple-aspen-config",
        ".plist": "application/xml",
    }

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def serve_https(root: Path, host: str, port: int, cert_path: Path, key_path: Path) -> None:
    handler = functools.partial(OTAHTTPRequestHandler, directory=str(root))
    httpd = ThreadingHTTPServer((host, port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"Serving HTTPS from {root}")
    print(f"Listening on https://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate iOS OTA manifest/install.html, optionally upload to OSS, and serve over HTTPS.",
    )
    parser.add_argument("--ipa", default=env("OTA_IPA"), help="IPA path. Defaults to the only *.ipa in cwd.")
    parser.add_argument(
        "--ipa-dir",
        default=env("OTA_IPA_DIR", "ipas"),
        help="Directory to search for an IPA when --ipa is not provided.",
    )
    parser.add_argument("--manifest", default=env("OTA_MANIFEST", "manifest.plist"))
    parser.add_argument("--html", default=env("OTA_HTML", "install.html"))
    parser.add_argument("--title", default=env("OTA_TITLE"), help="Override app title in manifest/page.")
    parser.add_argument("--host", default=env("OTA_HOST", "0.0.0.0"), help="Bind host for HTTPS server.")
    parser.add_argument("--port", type=int, default=int(env("OTA_PORT", str(DEFAULT_PORT))))
    parser.add_argument("--lan-host", default=env("OTA_LAN_HOST"), help="LAN IP or DNS name visible to the phone.")
    parser.add_argument("--base-url", default=env("OTA_BASE_URL"), help="Base URL for local generated files.")
    parser.add_argument("--cert-dir", default=env("OTA_CERT_DIR", ".certs"))
    parser.add_argument("--serve", action="store_true", help="Start an HTTPS server after generating files.")

    parser.add_argument("--upload-oss", action="store_true", default=env("OSS_UPLOAD") == "1")
    parser.add_argument("--oss-bucket", default=env("OSS_BUCKET"))
    parser.add_argument("--oss-endpoint", default=env("OSS_ENDPOINT"))
    parser.add_argument("--oss-prefix", default=env("OSS_PREFIX"))
    parser.add_argument("--oss-public-base-url", default=env("OSS_PUBLIC_BASE_URL"))
    parser.add_argument("--oss-access-key-id", default=env("ALIYUN_OSS_ACCESS_KEY_ID") or env("OSS_ACCESS_KEY_ID"))
    parser.add_argument(
        "--oss-access-key-secret",
        default=env("ALIYUN_OSS_ACCESS_KEY_SECRET") or env("OSS_ACCESS_KEY_SECRET"),
    )
    parser.add_argument("--oss-security-token", default=env("ALIYUN_OSS_SECURITY_TOKEN") or env("OSS_SECURITY_TOKEN"))
    parser.add_argument("--oss-acl", default=env("OSS_ACL"), help="Optional object ACL, for example public-read.")
    return parser


def main() -> None:
    root = Path.cwd()
    args = build_parser().parse_args()
    ipa_path = Path(args.ipa) if args.ipa else detect_ipa(root, args.ipa_dir)
    if not ipa_path.is_absolute():
        ipa_path = root / ipa_path
    if not ipa_path.exists():
        fail(f"IPA not found: {ipa_path}")

    metadata = load_ipa_metadata(ipa_path)
    if args.title:
        metadata["title"] = args.title

    lan_host = args.lan_host or guess_lan_host()
    local_base_url = args.base_url or f"https://{lan_host}:{args.port}"
    manifest_path = root / args.manifest
    html_path = root / args.html
    icon_path = extract_app_icon(ipa_path, root / "app-icon.png")
    full_icon_path = make_full_size_icon(icon_path, root / "app-icon-full.png")
    cert_paths: tuple[Path, Path, Path] | None = None
    cert_profile_path: Path | None = None

    if args.upload_oss:
        missing = [
            name
            for name, value in {
                "OSS_BUCKET": args.oss_bucket,
                "OSS_ENDPOINT": args.oss_endpoint,
                "ALIYUN_OSS_ACCESS_KEY_ID": args.oss_access_key_id,
                "ALIYUN_OSS_ACCESS_KEY_SECRET": args.oss_access_key_secret,
            }.items()
            if not value
        ]
        if missing:
            fail("missing OSS config: " + ", ".join(missing))

        default_prefix = f"ios-ota/{metadata['bundle_id']}/{metadata['version']}-{metadata['build']}"
        prefix = sanitize_prefix(args.oss_prefix or default_prefix)
        ipa_key = sanitize_prefix(f"{prefix}/{ipa_path.name}")
        manifest_key = sanitize_prefix(f"{prefix}/{manifest_path.name}")
        html_key = sanitize_prefix(f"{prefix}/{html_path.name}")
        icon_key = sanitize_prefix(f"{prefix}/{icon_path.name}") if icon_path else None
        full_icon_key = sanitize_prefix(f"{prefix}/{full_icon_path.name}") if full_icon_path else None
        public_base = args.oss_public_base_url or default_oss_public_base(args.oss_bucket, args.oss_endpoint)

        ipa_url = oss_object_url(public_base, ipa_key)
        manifest_url = oss_object_url(public_base, manifest_key)
        install_page_url = oss_object_url(public_base, html_key)
        icon_url = oss_object_url(public_base, icon_key) if icon_key else None
        full_icon_url = oss_object_url(public_base, full_icon_key) if full_icon_key else None
        mode = "OSS"
        cert_url = None
        cert_profile_url = None
    else:
        cert_paths = ensure_https_cert(root / args.cert_dir, lan_host)
        cert_profile_path = make_certificate_mobileconfig(
            cert_paths[2],
            root / args.cert_dir / "local-ota-cert.mobileconfig",
            lan_host,
        )
        ipa_url = join_url(local_base_url, url_path_for(root, ipa_path))
        manifest_url = join_url(local_base_url, manifest_path.name)
        install_page_url = join_url(local_base_url, html_path.name)
        icon_url = join_url(local_base_url, icon_path.name) if icon_path else None
        full_icon_url = join_url(local_base_url, full_icon_path.name) if full_icon_path else None
        mode = "Local HTTPS"
        cert_url = join_url(local_base_url, args.cert_dir, "server.cer")
        cert_profile_url = join_url(local_base_url, args.cert_dir, cert_profile_path.name)

    make_manifest(manifest_path, ipa_url, metadata, icon_url, full_icon_url)
    install_href = make_install_html(
        html_path,
        manifest_url,
        ipa_url,
        metadata,
        mode,
        cert_url,
        cert_profile_url,
    )

    print("Generated:")
    print(f"  manifest: {manifest_path}")
    print(f"  html:     {html_path}")
    print(f"  app:      {metadata['title']} {metadata['version']} ({metadata['build']})")
    print(f"  bundle:   {metadata['bundle_id']}")
    print(f"  page:     {install_page_url}")
    print(f"  manifest: {manifest_url}")
    print(f"  ipa:      {ipa_url}")
    if icon_url:
        print(f"  icon:     {icon_url}")
    if full_icon_url:
        print(f"  icon 512: {full_icon_url}")
    if cert_profile_url:
        print(f"  cert cfg: {cert_profile_url}")
    print(f"  install:  {install_href}")

    if args.upload_oss:
        assert args.oss_bucket and args.oss_endpoint and args.oss_access_key_id and args.oss_access_key_secret
        uploads = [
            (ipa_path, ipa_key),
            (manifest_path, manifest_key),
            (html_path, html_key),
        ]
        if icon_path and icon_key:
            uploads.append((icon_path, icon_key))
        if full_icon_path and full_icon_key:
            uploads.append((full_icon_path, full_icon_key))
        for file_path, object_key in uploads:
            print(f"Uploading {file_path.name} -> oss://{args.oss_bucket}/{object_key}")
            oss_put_file(
                file_path=file_path,
                bucket=args.oss_bucket,
                endpoint=args.oss_endpoint,
                object_key=object_key,
                access_key_id=args.oss_access_key_id,
                access_key_secret=args.oss_access_key_secret,
                security_token=args.oss_security_token,
                acl=args.oss_acl,
            )
        print(f"Uploaded install page: {install_page_url}")

    if args.serve:
        cert_path, key_path, _ = cert_paths or ensure_https_cert(root / args.cert_dir, lan_host)
        serve_https(root, args.host, args.port, cert_path, key_path)


if __name__ == "__main__":
    main()
