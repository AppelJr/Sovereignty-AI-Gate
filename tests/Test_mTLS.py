"""TEST FIXTURES: throwaway CAs and certificates for 127.0.0.1, plus locally signed tokens. Not a deployment and not your CA."""
import datetime, hashlib, http.client, ipaddress, json, ssl, subprocess, sys, tempfile, threading
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(Path(__file__).parent))
from gate_server import Gate, make_server
from test_gate_server_TEST import tok, JP, REALMS  # local-key token fixture

def _name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def mkca(cn):
    k = rsa.generate_private_key(65537, 2048); now = datetime.datetime.utcnow()
    c = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
         .not_valid_after(now + datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(k, hashes.SHA256())); return k, c
def issue(ca, cn, client, d, name):
    k = rsa.generate_private_key(65537, 2048); now = datetime.datetime.utcnow(); b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca[1].subject).public_key(k.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), False))
    if not client: b = b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
    c = b.sign(ca[0], hashes.SHA256()); cp, kp = d / f"{name}.pem", d / f"{name}.key"
    cp.write_bytes(c.public_bytes(serialization.Encoding.PEM)); kp.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return str(cp), str(kp), hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).digest()

def world(mode="required", **extra):
    d = Path(tempfile.mkdtemp()); ca, rogue = mkca("device-ca"), mkca("rogue-ca"); (d / "ca.pem").write_bytes(ca[1].public_bytes(serialization.Encoding.PEM))
    srv_c, srv_k, _ = issue(ca, "gate", False, d, "server"); dev = issue(ca, "device-1", True, d, "dev"); other = issue(ca, "device-2", True, d, "dev2"); bad = issue(rogue, "rogue-device", True, d, "rogue")
    data = d / "data"; data.mkdir()
    (data / "cards_medical.json").write_text(json.dumps([{"id": "TEST-medical-1", "name": "TEST medical", "provider": "TEST", "version": "t", "type": "text", "ctx": "N/A", "maxout": "N/A", "status": "current", "src": "test", "observed": "t", "who": "TEST", "what": "t", "when": "t", "where": "", "why": "", "how": "", "host": "t", "h8": "0"}]))
    cfg = {"data_dir": str(data), "allowed_hosts": ["127.0.0.1"], "client_id": "gate-pwa", "mtls": mode, "client_ca": str(d / "ca.pem"), "tls": {"cert": srv_c, "key": srv_k},
           "realms": {r: {"issuer": f"http://127.0.0.1:{JP}/realms/{r}", "jwks": f"http://127.0.0.1:{JP}/realms/{r}/certs", "auth": "x", "token": "x"} for r in REALMS}, **extra}
    g = Gate(cfg, ROOT); srv = make_server(g, "127.0.0.1", 0); threading.Thread(target=srv.serve_forever, daemon=True).start()
    return dict(d=d, g=g, port=srv.server_port, ca=str(d / "ca.pem"), dev=dev, other=other, bad=bad, data=data)

def req(w, cert=None, path="/api/ping", body="{}", token=None, method="POST"):
    ctx = ssl.create_default_context(cafile=w["ca"])
    if cert: ctx.load_cert_chain(cert[0], cert[1])
    c = http.client.HTTPSConnection("127.0.0.1", w["port"], context=ctx, timeout=10); c.request(method, path, body if method == "POST" else None, {"Content-Type": "application/json", **({"X-Gate-Token": token} if token else {})})
    r = c.getresponse(); return r.status, json.loads(r.read() or b"{}")

def test_required_mode_refuses_no_certificate_and_untrusted_certificate():
    w = world(); assert req(w, w["dev"], "/api/health", method="GET")[0] == 200
    for cert in (None, w["bad"]):
        with pytest.raises((OSError, http.client.HTTPException)): req(w, cert, "/api/health", method="GET")

def test_post_deploy_check_enforces_mtls_and_passes_with_a_device_certificate():
    w = world(); w["g"].scar("public", "TEST", x=1); from gate_crawler import Crawler; Crawler(w["g"].cfg).seed(ROOT / "public_catalog.json"); Crawler(w["g"].cfg).cycle(force=True)
    url = f"https://127.0.0.1:{w['port']}"; run = lambda *a: subprocess.run([sys.executable, str(ROOT / "gate_smoke.py"), url, "--cafile", w["ca"], *a], capture_output=True, text=True, timeout=60)
    ok = run("--cert", w["dev"][0], "--key", w["dev"][1]); print(ok.stdout); assert ok.returncode == 0 and "ALL PASS" in ok.stdout and "mTLS enforced" in ok.stdout
    no = run(); assert no.returncode != 0 and "PASS  mTLS enforced" in no.stdout

def test_a_valid_token_without_a_device_certificate_stays_public():
    w = world("optional"); t = tok("medical", n=31)[0]
    d, _ = (lambda r: (r[1], r[0]))(req(w, w["dev"], token=t)); assert d["tiers"] == ["public", "medical"]
    d = req(w, None, token=t)[1]; assert d["tiers"] == ["public"] and d["device_cert_required"] is True and "TEST-medical" not in json.dumps(d)

def test_tokens_bound_to_a_certificate_work_only_with_that_certificate():
    w = world(); x5t = lambda cert: __import__("base64").urlsafe_b64encode(cert[2]).rstrip(b"=").decode()
    good = tok("medical", n=32, cnf={"x5t#S256": x5t(w["dev"])})[0]
    assert req(w, w["dev"], token=good)[1]["tiers"] == ["public", "medical"]
    stolen = req(w, w["other"], token=good)[1]; assert stolen["tiers"] == ["public"] and stolen["token_invalid"] is True
    w2 = world(bind_tokens="require"); assert req(w2, w2["dev"], token=tok("medical", n=33)[0])[1]["token_invalid"] is True

def test_revoked_device_is_denied_and_the_denial_is_evidence():
    w = world(); fp = w["dev"][2].hex(); (w["data"] / "revoked_devices.txt").write_text(fp + "\n")
    s, d = req(w, w["dev"]); assert s == 403 and d["error"] == "device revoked"
    assert req(w, w["other"])[0] == 200 and fp in (w["data"] / "scar_public.jsonl").read_text() and "DEVICE_DENIED" in (w["data"] / "scar_public.jsonl").read_text()

def test_the_page_is_told_the_real_session():
    w = world(); s = req(w, w["dev"], token=tok("medical", n=41)[0])[1]["session"]
    assert s == {"mtls": "required", "device": w["dev"][2].hex(), "token": "unbound", "realm": "medical"} and req(w, w["dev"])[1]["session"]["token"] is None

def test_scar_records_which_device_saw_the_restricted_tier():
    w = world(); req(w, w["dev"], token=tok("medical", n=34)[0]); med = (w["data"] / "scar_medical.jsonl").read_text()
    assert "SESSION_GRANT" in med and w["dev"][2].hex() in med

def test_mtls_misconfiguration_fails_closed():
    d = Path(tempfile.mkdtemp())
    with pytest.raises(SystemExit): make_server(Gate({"data_dir": str(d), "realms": {}, "mtls": "required"}, ROOT), "127.0.0.1", 0)  # no TLS
    with pytest.raises(SystemExit): make_server(Gate({"data_dir": str(d), "realms": {}, "tls": {"cert": "x", "key": "y"}}, ROOT), "127.0.0.1", 0)  # no client_ca