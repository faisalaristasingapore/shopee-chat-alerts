#!/usr/bin/env python3
"""Shopee clout9sg chat unread poller (metadata-only alerts).

Runs on GitHub Actions. Because GitHub's scheduler only starts workflows
about every ~30 minutes (not the 5-min cron), each run polls in a tight
loop for ~35 minutes: refresh token, check sellerchat/get_conversation_list
(type=unread) every 2 minutes, and commit+push alerts.json immediately on
any change. This gives continuous ~2-minute detection granularity.

Tokens are kept encrypted in tokens.enc using TOKEN_PASSPHRASE (Fernet,
key derived via PBKDF2). After each refresh, tokens are re-encrypted and
committed so the next run picks up the rotated values.

alerts.json contains ONLY metadata (conversation_id, buyer username,
unread count, timestamp) — NO message content, NO credentials.
"""

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

API_HOST = "https://partner.shopeemobile.com"
# Loop duration: cover the gap until GitHub schedules the next run (~30 min)
# plus overlap. GitHub Actions allows up to 6h per run.
RUN_MINUTES = int(os.environ.get("POLL_MINUTES", "35"))
POLL_INTERVAL_SECS = 120


def log(msg):
    print(msg, flush=True)


def sign(base_string, partner_key):
    return hmac.new(
        partner_key.encode("utf-8"), base_string.encode("utf-8"),
        hashlib.sha256).hexdigest()


def api_call(partner_id, partner_key, api_path, access_token="",
             shop_id="", params=None, method="GET", body=None):
    ts = int(time.time())
    base = f"{partner_id}{api_path}{ts}{access_token}{shop_id}"
    query = {"partner_id": partner_id, "timestamp": ts,
             "sign": sign(base, partner_key)}
    if access_token:
        query["access_token"] = access_token
    if shop_id:
        query["shop_id"] = shop_id
    if params:
        query.update(params)
    url = API_HOST + api_path + "?" + urllib.parse.urlencode(query)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            payload = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return False, {"http_error": e.code}
    except Exception as e:
        return False, {"transport_error": str(e)[:100]}
    if payload.get("error"):
        return False, {"error": payload.get("error")}
    return True, payload.get("response", payload)


def fernet_key(passphrase):
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode(),
                             b"shopee-chat-alerts-v1", 100_000, 32)
    return base64.urlsafe_b64encode(dk)


def load_tokens(passphrase):
    from cryptography.fernet import Fernet
    with open("tokens.enc", "rb") as f:
        raw = Fernet(fernet_key(passphrase)).decrypt(f.read())
    return json.loads(raw.decode())


def save_tokens(passphrase, tokens):
    from cryptography.fernet import Fernet
    raw = Fernet(fernet_key(passphrase)).encrypt(
        json.dumps(tokens).encode())
    with open("tokens.enc", "wb") as f:
        f.write(raw)


def git_commit_push():
    subprocess.run(["git", "config", "user.name", "chat-unread-poller"],
                   check=False)
    subprocess.run(["git", "config", "user.email",
                    "chat-unread-poller@users.noreply.github.com"],
                   check=False)
    subprocess.run(["git", "add", "alerts.json", "tokens.enc"], check=False)
    r = subprocess.run(["git", "diff", "--cached", "--quiet"])
    if r.returncode != 0:
        subprocess.run(["git", "commit", "-m", "Update chat alerts"],
                       check=False)
        try:
            subprocess.run(["git", "push"], check=False, timeout=90)
        except subprocess.TimeoutExpired:
            log("PUSH_TIMEOUT_EXCEEDED")
            return
        log("PUSHED_UPDATE")
    else:
        log("NO_CHANGES")


def main():
    pid = os.environ["SHOPEE_ADS_PARTNER_ID"]
    pkey = os.environ["SHOPEE_ADS_PARTNER_KEY"]
    shop = os.environ["SHOPEE_SHOP_ID"]
    passphrase = os.environ["TOKEN_PASSPHRASE"]

    try:
        tokens = load_tokens(passphrase)
    except Exception:
        log("TOKENS_DECRYPT_FAILED")
        sys.exit(1)

    deadline = time.time() + RUN_MINUTES * 60
    iteration = 0
    while time.time() < deadline:
        iteration += 1
        # Refresh token each iteration (cheap, keeps it valid)
        ok, data = api_call(
            pid, pkey, "/api/v2/auth/access_token/get", method="POST",
            body={"partner_id": int(pid), "shop_id": int(shop),
                  "refresh_token": tokens.get("refresh_token", "")})
        if ok:
            tokens["access_token"] = data.get("access_token",
                                              tokens.get("access_token"))
            if data.get("refresh_token"):
                tokens["refresh_token"] = data["refresh_token"]
            save_tokens(passphrase, tokens)
            log(f"[{iteration}] REFRESH_OK")
        else:
            log(f"[{iteration}] REFRESH_FAIL {data}")

        access = tokens.get("access_token", "")
        ok, data = api_call(
            pid, pkey, "/api/v2/sellerchat/get_conversation_list",
            access_token=access, shop_id=shop,
            params={"direction": "latest", "type": "unread",
                    "page_size": 20})
        if not ok:
            log(f"[{iteration}] LIST_FAIL {data}")
        else:
            convs = data.get("conversations",
                             data.get("conversation_list", []))
            if isinstance(data, list):
                convs = data
            alerts = []
            for c in convs:
                if not isinstance(c, dict):
                    continue
                unread = int(c.get("unread_count", c.get("unread", 0)) or 0)
                if unread > 0:
                    alerts.append({
                        "conversation_id": str(c.get("conversation_id", "")),
                        "buyer": c.get("buyer_username",
                                       c.get("username", "")),
                        "unread_count": unread,
                        "seen_at": int(time.time()),
                    })
            payload = {"updated_at": int(time.time()), "alerts": alerts}
            new_text = json.dumps(payload, indent=1, sort_keys=True) + "\n"
            old_text = ""
            if os.path.exists("alerts.json"):
                with open("alerts.json", encoding="utf-8") as f:
                    old_text = f.read()
            if new_text != old_text:
                with open("alerts.json", "w", encoding="utf-8") as f:
                    f.write(new_text)
                log(f"[{iteration}] UNREAD={len(alerts)} ALERTS_UPDATED")
                git_commit_push()
            else:
                log(f"[{iteration}] UNREAD={len(alerts)} unchanged")

        # Sleep until next poll, but not past deadline
        remaining = deadline - time.time()
        if remaining > POLL_INTERVAL_SECS:
            time.sleep(POLL_INTERVAL_SECS)
        elif remaining > 0:
            time.sleep(remaining)
    log("LOOP_DONE")


if __name__ == "__main__":
    main()
