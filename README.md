# PortaNox v3.0 — Professional Secure LAN Chat

**Single‑file, zero‑dependency, end‑to‑encrypted chat server**  
Run it on your laptop, and anyone on the same network can join via browser.

![PortaNox](https://img.shields.io/badge/Python-3.7%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Features

- **Zero external dependencies** – pure Python 3.7+ standard library
- **Admin identity = your laptop IP** – no passwords, physical presence = admin
- **End‑to‑end encryption** (AES‑256‑GCM or XOR) – server never sees private/group content
- **Group chats** – PIN‑protected, creator owns & manages membership
- **Private 1‑on‑1 messages** – shared code encryption, blind routed
- **File sharing** – images, PDFs, ZIP, MP4, MP3, DOCX (max 15 MB)
- **Self‑destruct messages** – countdown timer, vanishes from all screens
- **No idle timeouts** – connections stay alive as long as browser is open
- **Mobile‑optimised** – touch‑friendly, bottom sheets, swipe‑in sidebar
- **Live admin dashboard** – approve joins, kick/ban/mute users, broadcast, view logs
- **Persistent history** – public & group messages survive restarts

---

## 🚀 Quick Start

### 1. Run the server on your laptop

```bash
python portanox_v3.py                # binds to port 5000
python portanox_v3.py --port 8080    # custom port
python portanox_v3.py --open         # auto‑approve all join requests (demo mode)
