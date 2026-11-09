# Chatly: username/password chat app

1:1 chats, group chats, read receipts (✓ sent, ✓✓ read, blue when everyone has read), and image sharing.

- **Server:** `server.py` (Flask + SQLite). Passwords are hashed, sessions use random tokens, images are checked by file signature and only visible to chat members.
- **App:** `static/` is a mobile-first web app (installable PWA). It polls every 1.5 s while a chat is open.
- **Tests:** `python3 -m unittest test_server -v`

## Run the server

```bash
pip install flask
python3 server.py        # http://0.0.0.0:5000
```

Open it on a phone browser (same Wi-Fi: `http://<your-computer-ip>:5000`), sign up two accounts and chat.

## Get an Android APK

The APK has to be built on a machine with the Android tooling, or with a web service. The app needs to be reachable at an **HTTPS** URL first (Render, Railway, Fly.io, a VPS with Caddy, etc.). Use a persistent disk for `chat.db` and `uploads/`.

**Easiest: PWABuilder (no installs)**
1. Deploy the server so you have `https://your-domain`.
2. Go to pwabuilder.com, enter the URL, choose Android, and download the package. It contains a signed APK/AAB.

**Alternative: Capacitor (full control)**
```bash
npm init -y && npm i @capacitor/core @capacitor/cli @capacitor/android
npx cap init Chatly com.example.chatly --web-dir=static
# in capacitor.config.json add:  "server": { "url": "https://your-domain" }
npx cap add android
npx cap open android      # Android Studio: Build > Build APK(s)
```

## Before real use

- Serve over HTTPS only (passwords and tokens travel in requests).
- Back up `chat.db` and `uploads/`.
- Messages are stored unencrypted on the server (this is not end-to-end encrypted like WhatsApp).
- Not included yet: push notifications, message deletion, password reset, profile photos.
- For many simultaneous users, run behind gunicorn instead of the Flask dev server.
