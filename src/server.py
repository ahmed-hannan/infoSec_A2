# Simple server skeleton for secure chat (application-layer cert exchange + DH + AES)
# Supports:
# - mutual certificate verification
# - DH + AES-128
# - encrypted registration/login using MariaDB
# - chat loop with seqno + replay detection
# - transcript logging + SessionReceipt for non-repudiation
import socket, json, threading, base64, argparse, secrets, hashlib, os, time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

from db.db import create_user, get_user_by_email
import auth


TRANSCRIPTS_DIR = "transcripts"


def ensure_dirs():
    os.makedirs(TRANSCRIPTS_DIR, exist_ok=True)


def load_pem(path):
    return Path(path).read_bytes()


def cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def verify_cert_signed_by_ca(cert_pem, ca_cert):
    cert = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    return cert


def derive_aes_key_from_shared(shared_bytes):
    h = hashlib.sha256(shared_bytes).digest()
    return h[:16]  # AES-128


def aes_encrypt(key, plaintext: bytes) -> bytes:
    iv = secrets.token_bytes(16)
    padder = sym_padding.PKCS7(128).padder()
    pt = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor().update(pt) + cipher.encryptor().finalize()
    return iv + enc  # prepend iv


def aes_decrypt(key, data: bytes) -> bytes:
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    unpad = sym_padding.PKCS7(128).unpadder()
    return unpad.update(dec) + unpad.finalize()


def handle_auth_phase(sock, aes_key):
    """Handle a single encrypted auth (register/login) exchange."""
    raw = sock.recv(65536)
    if not raw:
        print("client closed before auth")
        return False

    msg = json.loads(raw.decode())
    if msg.get("type") != "auth":
        print("expected auth message, got:", msg.get("type"))
        return False

    ct = base64.b64decode(msg["ct"])
    try:
        inner_bytes = aes_decrypt(aes_key, ct)
        inner = json.loads(inner_bytes.decode())
    except Exception as e:
        print("auth decrypt/parse error:", e)
        return False

    mtype = inner.get("type")
    email = inner.get("email")
    password = inner.get("password")  # arrives only inside AES

    if mtype == "register":
        username = inner.get("username")
        print(f"auth: register email={email}, username={username}")

        salt = auth.generate_salt()
        pwd_hash = auth.hash_password(password, salt)
        ok = create_user(email, username, salt, pwd_hash)
        if ok:
            status = "ok"
            message = "registration successful"
        else:
            status = "error"
            message = "username already exists"

    elif mtype == "login":
        print(f"auth: login email={email}")
        row = get_user_by_email(email)
        if not row:
            status = "error"
            message = "no such user"
        else:
            salt = row["salt"]         # bytes
            stored_hash = row["pwd_hash"]  # hex string
            if auth.verify_password(salt, stored_hash, password):
                status = "ok"
                message = "login successful"
            else:
                status = "error"
                message = "invalid password"
    else:
        status = "error"
        message = f"unknown auth type {mtype}"

    resp_inner = {"status": status, "message": message}
    resp_ct = aes_encrypt(aes_key, json.dumps(resp_inner).encode())
    resp_msg = {"type": "auth_resp", "ct": base64.b64encode(resp_ct).decode()}
    sock.send(json.dumps(resp_msg).encode())

    print("auth phase result:", status, "-", message)
    return status == "ok"


def handle_client(sock, addr, args):
    print("client connected", addr)

    # Load server private key for signing receipts
    server_priv = serialization.load_pem_private_key(
        Path(args.server_key).read_bytes(), password=None, backend=default_backend()
    )

    # 1) receive client hello JSON
    raw = sock.recv(65536)
    if not raw:
        print("client closed immediately")
        sock.close()
        return
    hello = json.loads(raw.decode())
    client_cert_pem = base64.b64decode(hello["client_cert"])
    client_nonce = base64.b64decode(hello["nonce"])
    print("received client hello, nonce len", len(client_nonce))

    # 2) send server hello with server cert and nonce
    server_cert_pem = load_pem(args.server_cert)
    with open(args.ca_cert, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
    # verify client cert signature
    try:
        client_cert = verify_cert_signed_by_ca(client_cert_pem, ca_cert)
        print("client cert verified OK for subject:", client_cert.subject)
    except Exception as e:
        print("client cert verification FAILED:", e)
        sock.send(b'{"error":"bad client cert"}')
        sock.close()
        return

    client_fpr = cert_fingerprint_sha256(client_cert)

    server_nonce = secrets.token_bytes(16)
    server_hello = {
        "type": "server_hello",
        "server_cert": base64.b64encode(server_cert_pem).decode(),
        "nonce": base64.b64encode(server_nonce).decode(),
    }
    sock.send(json.dumps(server_hello).encode())

    # 3) Server generates DH parameters & key, sends params + pubkey
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    server_priv_dh = parameters.generate_private_key()
    server_pub = server_priv_dh.public_key()
    params_numbers = parameters.parameter_numbers()
    p_int = params_numbers.p
    g_int = params_numbers.g
    server_pub_bytes = server_pub.public_numbers().y.to_bytes(
        (server_pub.public_numbers().y.bit_length() + 7) // 8, "big"
    )
    params_msg = {
        "type": "dh_params",
        "p": str(p_int),
        "g": str(g_int),
        "server_pub": base64.b64encode(server_pub_bytes).decode(),
    }
    sock.send(json.dumps(params_msg).encode())

    # 4) receive client pub, compute shared key
    raw = sock.recv(65536)
    if not raw:
        print("client closed before sending DH pub")
        sock.close()
        return
    msg = json.loads(raw.decode())
    client_pub_bytes = base64.b64decode(msg["client_pub"])
    client_pub_int = int.from_bytes(client_pub_bytes, "big")
    client_pub_numbers = dh.DHPublicNumbers(client_pub_int, parameters.parameter_numbers())
    client_pub_key = client_pub_numbers.public_key(backend=default_backend())
    shared = server_priv_dh.exchange(client_pub_key)
    aes_key = derive_aes_key_from_shared(shared)
    print("derived aes key len", len(aes_key))

    # 5) AUTH PHASE (register/login over encrypted channel)
    if not handle_auth_phase(sock, aes_key):
        print("auth failed, closing connection")
        sock.close()
        return

    # 6) CHAT LOOP: receive multiple messages with seqno + replay detection
    last_seqno = 0
    transcript_lines = []
    first_seq = None
    last_seq = None
    session_id = secrets.token_hex(8)
    transcript_path = os.path.join(TRANSCRIPTS_DIR, f"server_transcript_{session_id}.log")
    print("entering chat loop for", addr, "session_id=", session_id)

    while True:
        raw = sock.recv(65536)
        if not raw:
            print("client disconnected", addr)
            break

        try:
            m = json.loads(raw.decode())
        except Exception as e:
            print("invalid JSON from client:", e)
            break

        if m.get("type") != "msg":
            print("ignoring non-msg type:", m.get("type"))
            continue

        ct = base64.b64decode(m["ct"])
        sig = base64.b64decode(m["sig"])
        seqno = m.get("seqno", 0)
        ts = m.get("ts", 0)

        # replay / out-of-order protection
        if seqno <= last_seqno:
            print(f"REPLAY/OUT-OF-ORDER detected: got seqno={seqno}, last_seqno={last_seqno}")
            break

        # Verify signature with client's public key
        try:
            client_pub = client_cert.public_key()
            h = hashlib.sha256((str(seqno) + str(ts)).encode() + ct).digest()
            client_pub.verify(sig, h, padding.PKCS1v15(), hashes.SHA256())
            print(f"signature valid for seqno={seqno}")
        except Exception as e:
            print("signature verify FAILED:", e)
            break

        try:
            pt = aes_decrypt(aes_key, ct)
            print(f"[{addr}] seq={seqno} ts={ts} msg: {pt.decode(errors='ignore')}")
        except Exception as e:
            print("decrypt failed:", e)
            break

        # Append to transcript (append-only log)
        ct_b64 = base64.b64encode(ct).decode()
        sig_b64 = base64.b64encode(sig).decode()
        line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{client_fpr}\n"
        transcript_lines.append(line.encode())

        # Also write to disk as append-only file
        with open(transcript_path, "ab") as f:
            f.write(line.encode())

        if first_seq is None:
            first_seq = seqno
        last_seq = seqno
        last_seqno = seqno

    # After chat loop: generate SessionReceipt if we have any messages
    if transcript_lines and first_seq is not None and last_seq is not None:
        transcript_bytes = b"".join(transcript_lines)
        digest_bytes = hashlib.sha256(transcript_bytes).digest()
        digest_hex = digest_bytes.hex()

        receipt = {
            "type": "receipt",
            "side": "server",
            "peer": "client",
            "session_id": session_id,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": digest_hex,
            "peer_cert_fingerprint": client_fpr,
        }

        sig = server_priv.sign(digest_bytes, padding.PKCS1v15(), hashes.SHA256())
        receipt["sig"] = base64.b64encode(sig).decode()

        receipt_path = os.path.join(TRANSCRIPTS_DIR, f"server_receipt_{session_id}.json")
        with open(receipt_path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=2)
        print("SessionReceipt written to", receipt_path)

    sock.close()


def main():
    ensure_dirs()
    p = argparse.ArgumentParser()
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--server-cert", default="certs/server.example.cert.pem")
    p.add_argument("--server-key", default="certs/server.example.key.pem")
    p.add_argument("--ca-cert", default="certs/ca.cert.pem")
    args = p.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((args.bind, args.port))
    s.listen(5)
    print("listening on", args.bind, args.port)
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr, args)).start()
    finally:
        s.close()


if __name__ == "__main__":
    main()
