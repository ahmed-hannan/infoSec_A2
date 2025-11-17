# 🔐 Secure Chat System — Assignment 2  
**Course:** Information Security  
**Student:** 22i-0943 — Ahmed Hannan  
**Institution:** FAST NUCES  

---

## 📌 Overview

This project is a secure client–server chat system implemented entirely at the **application layer**, without relying on TLS or external security frameworks.  
It demonstrates the core CIANR security goals:

| Security Property | Mechanism Used |
|------------------|----------------|
| **Confidentiality** | AES-128 (CBC + PKCS7), per-message IV |
| **Integrity** | RSA-PKCS#1 v1.5 Signatures |
| **Authentication** | X.509 Certificates, CA-signed, validated on both sides |
| **Non-Repudiation** | Signed SessionReceipts + Transcript Hash |
| **Replay Protection** | Incrementing `seqno` + server-side state |

---

## 🧠 Architecture Summary

| Component | Purpose |
|----------|---------|
| `gen_ca.py` | Creates a Root CA and keys |
| `gen_cert.py` | Issues server/client certificates signed by CA |
| `server.py` | Accepts clients, validates certificates, performs DH key exchange, login/registration, transcript + receipt |
| `client.py` | Connects to server, verifies certs, performs DH, sends encrypted messages |
| `verify_receipt.py` | Offline verification tool (receipt signature + transcript integrity) |
| Test Scripts | Validate attacks (invalid cert, replay, tampering) |

---

## 🗄️ Folder Structure

infoSec_A2/
│
├── certs/ # Generated certificates (NO private keys committed)
├── certs_bad/ # Fake certs for invalid client test
├── scripts/ # PKI setup utilities
├── src/ # Application code
│ ├── server.py
│ ├── client.py
│ ├── verify_receipt.py
│ ├── auth.py
│ ├── db/
│ │ ├── db.py
│ │ └── securechat_schema_dump.sql
│
├── transcripts/ # Logs & signed receipts generated during testing
├── test/ # Attack test scripts
│ ├── test_invalid_cert_client.py
│ ├── test_replay_attack.py
│ ├── test_tamper_attack.py
│
├── Docs/
│ ├── 22i-0943_AhmedHannan_Report-A02.docx
│ ├── 22i-0943_AhmedHannan_TestReport-A02.docx
│
├── requirements.txt
├── .env.example
└── README.md (this file)

yaml
Copy code

---

## ⚙️ Installation & Setup

### 1️⃣ Clone repository

```bash
git clone https://github.com/ahmed-hannan/infoSec_A2
cd infoSec_A2
2️⃣ Create and activate virtual environment
bash
Copy code
python3 -m venv venv
source venv/bin/activate
3️⃣ Install dependencies
bash
Copy code
pip install -r requirements.txt
4️⃣ Setup MariaDB / MySQL
bash
Copy code
sudo mysql -u root
sql
Copy code
CREATE DATABASE securechat;
CREATE USER 'chatuser'@'localhost' IDENTIFIED BY 'StrongPassword123!';
GRANT ALL PRIVILEGES ON securechat.* TO 'chatuser'@'localhost';
FLUSH PRIVILEGES;
Then load schema:

bash
Copy code
mysql -u chatuser -p securechat < src/db/securechat_schema_dump.sql
🔐 Generating Certificates
bash
Copy code
python3 scripts/gen_ca.py --outdir certs --cn "SecureChat CA"

python3 scripts/gen_cert.py \
  --ca-key certs/ca.key.pem \
  --ca-cert certs/ca.cert.pem \
  --cn server.example \
  --type server \
  --outdir certs

python3 scripts/gen_cert.py \
  --ca-key certs/ca.key.pem \
  --ca-cert certs/ca.cert.pem \
  --cn client.example \
  --type client \
  --outdir certs
▶️ Running the System
Terminal 1 — Start Server
bash
Copy code
export DB_HOST=localhost DB_USER=chatuser DB_PASS='StrongPassword123!' DB_NAME=securechat
python3 src/server.py
Terminal 2 — Client Login
bash
Copy code
python3 src/client.py --mode login \
  --email test@example.com \
  --password mysecret
🧪 Security Test Scripts
Attack	Expected Result	Script
Invalid Certificate	Server rejects client	test_invalid_cert_client.py
Replay	Server detects duplicate seq	test_replay_attack.py
Tampered Ciphertext	Signature verification failure	test_tamper_attack.py

Example:

bash
Copy code
python3 test/test_tamper_attack.py
✔️ Receipt Verification (Non-Repudiation Proof)
bash
Copy code
python3 src/verify_receipt.py \
  --transcript transcripts/server_transcript_<id>.log \
  --receipt transcripts/server_receipt_<id>.json \
  --cert certs/client.example.cert.pem
Expected:

csharp
Copy code
[OK] Transcript hash matches receipt.
[OK] Signature on transcript hash is valid.
[SUCCESS] Receipt is valid.