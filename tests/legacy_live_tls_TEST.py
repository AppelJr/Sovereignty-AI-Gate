"""TEST FIXTURE: a throwaway self-signed certificate for 127.0.0.1. Proves the TLS path and the post-deploy check. Not a deployment."""
import datetime, ipaddress, subprocess, sys, tempfile, threading
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from gate_server import Gate, make_server, check_port
from gate_crawler import Crawler

def test_only_443_and_the_9000s_are_allowed():
    for p in (443, 9443, 9000, 9999, 0): check_port(p)
    for p in (80, 22, 7001, 10000):
        with pytest.raises(SystemExit): check_port(p)

def test_tls_server_passes_the_post_deploy_check_and_untrusted_clients_fail():
    d = Path(tempfile.mkdtemp()); k = rsa.generate_private_key(65537, 2048); n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gate-test")]); now = datetime.datetime.utcnow()
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
         .not_valid_after(now + datetime.timedelta(days=30)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(k, hashes.SHA256()))
    (d / "c.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM)); (d / "k.pem").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    cfg = {"data_dir": str(d / "data"), "allowed_hosts": ["127.0.0.1"], "realms": {}, "mtls": "off", "tls": {"cert": str(d / "c.pem"), "key": str(d / "k.pem")}}
    cr = Crawler(cfg); cr.seed(ROOT / "public_catalog.json"); cr.cycle(force=True)
    srv = make_server(Gate(cfg, ROOT), "127.0.0.1", 0); threading.Thread(target=srv.serve_forever, daemon=True).start(); url = f"https://127.0.0.1:{srv.server_port}"
    ok = subprocess.run([sys.executable, str(ROOT / "gate_smoke.py"), url, "--cafile", str(d / "c.pem"), "--allow-anonymous"], capture_output=True, text=True, timeout=60); print(ok.stdout)
    assert ok.returncode == 0 and "FAIL" not in ok.stdout and "ALL PASS" in ok.stdout
    bad = subprocess.run([sys.executable, str(ROOT / "gate_smoke.py"), url], capture_output=True, text=True, timeout=60)
    assert bad.returncode != 0 and "FAIL" in bad.stdout
