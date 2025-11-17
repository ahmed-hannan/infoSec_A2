# Simple client skeleton to talk to server.py
# Supports encrypted registration/login and a simple interactive chat loop,
# plus transcript logging + SessionReceipt on the client side.
import socket, json, base64, argparse, secrets, hashlib, os, time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


TRANSCRIPTS_DIR = "transcripts"


def ensure_dirs():
    os.makedirs(TRANSCRIPTS_DIR, exist_ok=True)


def load_pem(path):
    return Path(path).read_bytes()


def cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def derive_aes_key_from_shared(shared_bytes):
    h = hashlib.sha256(shared_bytes).digest()
    return h[:16]


def aes_encrypt(key, plaintext: bytes) -> bytes:
    iv = secrets.token_bytes(16)
    padder = sym_padding.PKCS7(128).padder()
    pt = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor().update(pt) + cipher.encryptor().finalize()
    return iv + enc


def aes_decrypt(key, data: bytes) -> bytes:
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    unpad = sym_padding.PKCS7(128).unpadder()
    return unpad.update(dec) + unpad.finalize()


def main():
    ensure_dirs()

    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--client-cert", default="certs/client.example.cert.pem")
    p.add_argument("--client-key", default="certs/client.example.key.pem")
    p.add_argument("--ca-cert", default="certs/ca.cert.pem")

    # auth options
    p.add_argument(
        "--mode",
        choices=["register", "login"],
        default="login",
        help="client mode: register or login before chat message",
    )
    p.add_argument("--email")
    p.add_argument("--username")
    p.add_argument("--password")

    args = p.parse_args()

    if not args.email or not args.password:
        raise SystemExit("You must provide --email and --password (and --username for register)")

    if args.mode == "register" and not args.username:
        raise SystemExit("In register mode you must provide --username as well")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((args.host, args.port))

    # 1) send client hello
    client_cert_pem = load_pem(args.client_cert)
    nonce = secrets.token_bytes(16)
    hello = {
        "type": "hello",
        "client_cert": base64.b64encode(client_cert_pem).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }
    s.send(json.dumps(hello).encode())

    # 2) receive server hello & verify cert
    raw = s.recv(65536)
    server_hello = json.loads(raw.decode())
    server_cert_pem = base64.b64decode(server_hello["server_cert"])
    server_nonce = base64.b64decode(server_hello["nonce"])

    ca_cert = x509.load_pem_x509_certificate(
        Path(args.ca_cert).read_bytes(), backend=default_backend()
    )
    server_cert = x509.load_pem_x509_certificate(server_cert_pem, backend=default_backend())
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        server_cert.signature,
        server_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        server_cert.signature_hash_algorithm,
    )
    print("server cert verified OK")

    server_fpr = cert_fingerprint_sha256(server_cert)

    # 3) receive DH params
    raw = s.recv(65536)
    params = json.loads(raw.decode())
    p_int = int(params["p"])
    g_int = int(params["g"])
    server_pub_bytes = base64.b64decode(params["server_pub"])
    server_pub_int = int.from_bytes(server_pub_bytes, "big")

    # 4) send client DH pubkey and derive shared
    parameters = dh.DHParameterNumbers(p_int, g_int).parameters(backend=default_backend())
    client_priv_dh = parameters.generate_private_key()
    client_pub_dh = client_priv_dh.public_key()
    client_pub_bytes = client_pub_dh.public_numbers().y.to_bytes(
        (client_pub_dh.public_numbers().y.bit_length() + 7) // 8, "big"
    )
    client_pub_msg = {"type": "client_pub", "client_pub": base64.b64encode(client_pub_bytes).decode()}
    s.send(json.dumps(client_pub_msg).encode())

    server_pub_numbers = dh.DHPublicNumbers(server_pub_int, parameters.parameter_numbers())
    server_pub_key = server_pub_numbers.public_key(backend=default_backend())
    shared = client_priv_dh.exchange(server_pub_key)
    aes_key = derive_aes_key_from_shared(shared)

    # 5) AUTH PHASE (register or login)
    inner = {
        "type": args.mode,
        "email": args.email,
        "password": args.password,
    }
    if args.mode == "register":
        inner["username"] = args.username

    inner_bytes = json.dumps(inner).encode()
    ct_auth = aes_encrypt(aes_key, inner_bytes)
    auth_msg = {"type": "auth", "ct": base64.b64encode(ct_auth).decode()}
    s.send(json.dumps(auth_msg).encode())

    raw = s.recv(65536)
    resp = json.loads(raw.decode())
    if resp.get("type") != "auth_resp":
        print("expected auth_resp, got:", resp)
        s.close()
        return

    resp_ct = base64.b64decode(resp["ct"])
    resp_inner = json.loads(aes_decrypt(aes_key, resp_ct).decode())
    print("Auth result:", resp_inner)

    if resp_inner.get("status") != "ok":
        print("Auth failed, not entering chat.")
        s.close()
        return

    # 6) CHAT LOOP: send multiple messages with seqno, and log transcript
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

    client_priv_key = serialization.load_pem_private_key(
        Path(args.client_key).read_bytes(), password=None, backend=default_backend()
    )

    seqno = 0
    transcript_lines = []
    first_seq = None
    last_seq = None
    session_id = secrets.token_hex(8)
    transcript_path = os.path.join(TRANSCRIPTS_DIR, f"client_transcript_{session_id}.log")

    print("You can now type messages. Type /quit to exit.")

    try:
        while True:
            try:
                text = input("> ")
            except EOFError:
                break

            if text.strip() == "/quit":
                print("Exiting chat.")
                break

            if not text.strip():
                continue

            seqno += 1
            ts = int(time.time() * 1000)
            plaintext = text.encode("utf-8")

            ct = aes_encrypt(aes_key, plaintext)

            h = hashlib.sha256((str(seqno) + str(ts)).encode() + ct).digest()
            sig = client_priv_key.sign(h, asym_padding.PKCS1v15(), hashes.SHA256())

            msg = {
                "type": "msg",
                "seqno": seqno,
                "ts": ts,
                "ct": base64.b64encode(ct).decode(),
                "sig": base64.b64encode(sig).decode(),
            }
            s.send(json.dumps(msg).encode())
            print(f"sent seq={seqno}")

            # Append to transcript
            ct_b64 = base64.b64encode(ct).decode()
            sig_b64 = base64.b64encode(sig).decode()
            line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{server_fpr}\n"
            transcript_lines.append(line.encode())

            with open(transcript_path, "ab") as f:
                f.write(line.encode())

            if first_seq is None:
                first_seq = seqno
            last_seq = seqno

    finally:
        # Generate SessionReceipt on client side
        if transcript_lines and first_seq is not None and last_seq is not None:
            transcript_bytes = b"".join(transcript_lines)
            digest_bytes = hashlib.sha256(transcript_bytes).digest()
            digest_hex = digest_bytes.hex()

            receipt = {
                "type": "receipt",
                "side": "client",
                "peer": "server",
                "session_id": session_id,
                "first_seq": first_seq,
                "last_seq": last_seq,
                "transcript_sha256": digest_hex,
                "peer_cert_fingerprint": server_fpr,
            }

            sig = client_priv_key.sign(digest_bytes, asym_padding.PKCS1v15(), hashes.SHA256())
            receipt["sig"] = base64.b64encode(sig).decode()

            receipt_path = os.path.join(TRANSCRIPTS_DIR, f"client_receipt_{session_id}.json")
            with open(receipt_path, "w", encoding="utf-8") as f:
                json.dump(receipt, f, indent=2)
            print("Client SessionReceipt written to", receipt_path)

        s.close()


if __name__ == "__main__":
    main()
