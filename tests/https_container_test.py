"""Opt-in native Apache TLS drill, no production project and no public listener.

python tests/https_container_test.py --run
Uses a cached web image, an isolated image/container and an ephemeral local test
certificate. No external network or production container is accessed.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recovery", ROOT / "scripts" / "backup_restore.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    if not parser.parse_args().run: parser.error("Use --run for an isolated, loopback-only HTTPS test.")
    suffix = uuid.uuid4().hex[:10]
    name = "cybershield-https-drill-" + suffix
    image = "cybershield-https-drill:" + suffix
    base = recovery.private_directory(ROOT / "tmp" / name)
    certificates = base / "certificates"
    certificates.mkdir()
    context = base / "build"
    context.mkdir()
    for source, target in ((ROOT / "app/RequestTransport.php", "RequestTransport.php"),
                           (ROOT / "security/tls-request.php", "tls-request.php"),
                           (ROOT / "docker/php/tls-cybershield.conf", "tls-cybershield.conf")):
        shutil.copyfile(source, context / target)
    (context / "Dockerfile").write_text(
        "FROM projet_tutor_inf-web:latest\n"
        "COPY RequestTransport.php /var/www/html/app/RequestTransport.php\n"
        "COPY tls-request.php /var/www/html/security/tls-request.php\n"
        "COPY tls-cybershield.conf /etc/apache2/conf-available/cybershield-tls.conf\n"
        "COPY probe.php /var/www/html/tls-probe.php\n"
        "RUN a2enmod ssl && a2enconf cybershield-tls\n", encoding="utf-8")
    (context / "probe.php").write_text(
        '<?php require "/var/www/html/security/tls-request.php"; cybershield_require_secure_transport(); '
        'session_set_cookie_params(RequestTransport::cookieOptions()); session_start(); '
        'header("Content-Type: application/json"); echo json_encode(["https"=>RequestTransport::isHttps()]);', encoding="utf-8")
    build_env = dict(os.environ, DOCKER_BUILDKIT="0")
    result = subprocess.run(["docker", "build", "--network", "none", "-t", image, str(context)],
                            env=build_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode: raise AssertionError("Isolated cached-image TLS build failed")
    recovery.docker("run", "--rm", "--network", "none", "--entrypoint", "openssl",
                    "--mount", f"type=bind,source={certificates},target=/certs", image,
                    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    "-keyout", "/certs/server.key", "-out", "/certs/server.crt")
    container = None
    try:
        container = recovery.docker("run", "-d", "--name", name, "--network", "none",
                        "--env", "CYBERSHIELD_REQUIRE_HTTPS=1", "--tmpfs", "/var/lib/cybershield",
                        "--mount", f"type=bind,source={certificates / 'server.crt'},target=/run/secrets/tls_certificate,readonly",
                        "--mount", f"type=bind,source={certificates / 'server.key'},target=/run/secrets/tls_private_key,readonly",
                        image, "apache2-foreground", "-D", "CYBERSHIELD_TLS").decode().strip()
        state = recovery.inspect(container)
        # Request the server from its own network namespace: no host ports or egress.
        # Verification uses this test's CA certificate, never insecure TLS bypass.
        curl = ('$c=curl_init($argv[1]);curl_setopt_array($c,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_HEADER=>true,'
                'CURLOPT_CAINFO=>"/run/secrets/tls_certificate",CURLOPT_TIMEOUT=>3,'
                'CURLOPT_HTTPHEADER=>["X-Forwarded-Proto: https"]]);'
                '$r=curl_exec($c);if($r===false){exit(9);}echo json_encode(["status"=>curl_getinfo($c,CURLINFO_HTTP_CODE),"response"=>$r]);')
        for _ in range(30):
            try:
                response = json.loads(recovery.docker("exec", container, "php", "-r", curl, "https://127.0.0.1/tls-probe.php"))
                break
            except recovery.RecoveryError: time.sleep(0.3)
        else: raise AssertionError("Native Apache HTTPS was not reachable")
        assert response["status"] == 200 and '"https":true' in response["response"]
        headers = response["response"].split("\r\n\r\n", 1)[0]
        cookie = next(line.lower() for line in headers.split("\r\n") if line.lower().startswith("set-cookie:"))
        assert "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie
        assert "strict-transport-security: max-age=" in headers.lower()
        http = json.loads(recovery.docker("exec", container, "php", "-r", curl, "http://127.0.0.1/tls-probe.php"))
        assert http["status"] == 426 and "set-cookie:" not in http["response"].lower()
        report = {"passed": True, "native_tls": True, "secure_cookie": True, "http_spoof_refused": True,
                  "no_published_ports": state["HostConfig"]["PortBindings"] in (None, {}), "network_none": True}
        recovery.write_private(base / "https-result.json", json.dumps(report, indent=2).encode())
        print(json.dumps(report))
    finally:
        if container: recovery.docker("stop", "--time", "10", container, timeout=25)


if __name__ == "__main__": main()
