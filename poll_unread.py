#!/usr/bin/env python3
"""Shopee clout9sg chat unread poller (metadata-only alerts).

Refreshes the Shopee access token, polls sellerchat/get_conversation_list,
and writes metadata-only alerts to alerts.json (no message content is stored).
Tokens are kept encrypted in tokens.enc using TOKEN_PASSPHRASE.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = "https://partner.shopeemobile.com"
REFRESH = "/api/v2/auth/access_token/get"
CONVO = "/api/v2/sellerchat/get_conversation_list"
TIME_FIELDS = ("latest_message_time", "last_message_time",
               "latest_message_timestamp", "last_message_timestamp")


def sign(base, key):
    return hmac.new(key.encode(), base.encode(), hashlib.sha256).hexdigest()


def fernet_key(passphrase):
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode(),
                             b"shopee-chat-alerts-v1", 100_000, 32)
    return base64.urlsafe_b64encode(dk)


def load_tokens(passphrase):
    from cryptography.fernet import Fernet
    with open("tokens.enc", "rb") as f:
        raw = Fernet(fernet_key(passphrase)).decrypt(f.read())
    return json.loads(raw.decode())


def save_tokens(passphrase, toks):
    from cryptography.fernet import Fernet
    blob = Fernet(fernet_key(passphrase)).encrypt(json.dumps(toks).encode())
    with open("tokens.enc", "wb") as f:
        f.write(blob)


def call(pid, pkey, path, tok="", shop="", params=None, method="GET", body=None):
    ts = int(time.time())
    q = {"partner_id": pid, "timestamp": ts,
         "sign": sign("%s%s%s%s%s" % (pid, path, ts, tok, shop), pkey)}
    if tok:
        q["access_token"] = tok
    if shop:
        q["shop_id"] = shop
    if params:
        q.update(params)
    url = HOST + path + "?" + urllib.parse.urlencode(q)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            payload = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return False, {"http_error": e.code,
                       "body": e.read().decode("utf8", "replace")[:300]}
    except Exception as e:
        return False, {"transport_error": str(e)[:300]}
    if payload.get("error"):
        return False, payload
    return True, payload.get("response", payload)


def short_err(d):
    if isinstance(d, dict):
        return "error=%r message=%r http=%s body=%r" % (
            d.get("error"), d.get("message"), d.get("http_error", ""),
            str(d.get("body", ""))[:200])
    return str(d)[:200]


def main():
    pid = os.environ.get("SHOPEE_ADS_PARTNER_ID", "").strip()
    pkey = os.environ.get("SHOPEE_ADS_PARTNER_KEY", "").strip()
    shop = os.environ.get("SHOPEE_SHOP_ID", "").strip()
    pw = os.environ.get("TOKEN_PASSPHRASE", "").strip()
    miss = [n for n, v in (("SHOPEE_ADS_PARTNER_ID", pid),
                           ("SHOPEE_ADS_PARTNER_KEY", pkey),
                           ("SHOPEE_SHOP_ID", shop),
                           ("TOKEN_PASSPHRASE", pw)) if not v]
    if miss:
        print("MISSING_ENV:", ",".join(miss), flush=True)
        return 1
    try:
        toks = load_tokens(pw)
    except FileNotFoundError:
        print("TOKENS_MISSING: run the One-time OAuth code exchange first",
              flush=True)
        return 1
    except Exception:
        print("TOKENS_DECRYPT_FAILED", flush=True)
        return 1
    rtok = toks.get("refresh_token", "") if isinstance(toks, dict) else ""
    if not rtok:
        print("REFRESH_FAILED: no refresh_token stored", flush=True)
        return 1
    ok, data = call(pid, pkey, REFRESH, method="POST",
                    body={"partner_id": int(pid), "shop_id": int(shop),
                          "refresh_token": rtok})
    if not ok:
        print("REFRESH_FAILED", short_err(data), flush=True)
        return 1
    if not isinstance(data, dict) or not data.get("access_token"):
        print("REFRESH_FAILED: no access_token in response", flush=True)
        return 1
    toks["access_token"] = data["access_token"]
    if data.get("refresh_token"):
        toks["refresh_token"] = data["refresh_token"]
    try:
        save_tokens(pw, toks)
    except Exception:
        print("TOKENS_STORE_FAILED", flush=True)
        return 1
    print("REFRESH_OK", flush=True)
    ok, data = call(pid, pkey, CONVO, toks["access_token"], shop,
                    params={"direction": "latest", "type": "all",
                            "page_size": 20})
    if not ok:
        print("CONVERSATION_LIST_FAILED", short_err(data), flush=True)
        return 1
    convos = data.get("conversations", []) if isinstance(data, dict) else []
    if not isinstance(convos, list):
        convos = []
    total_unread = 0
    alerts = []
    for c in convos:
        if not isinstance(c, dict):
            continue
        try:
            unread = int(c.get("unread_count") or 0)
        except (TypeError, ValueError):
            unread = 0
        total_unread += unread
        if unread > 0:
            alert = {"shop_id": int(shop),
                     "conversation_id": c.get("conversation_id"),
                     "buyer": c.get("to_name") or c.get("username"),
                     "unread_count": unread}
            for f in TIME_FIELDS:
                if c.get(f):
                    alert["latest_message_time"] = c.get(f)
                    break
            alerts.append(alert)
    alerts.sort(key=lambda a: a["unread_count"], reverse=True)
    with open("alerts.json", "w") as f:
        json.dump({"updated_at": int(time.time()), "alerts": alerts}, f,
                  indent=2)
    print("UNREAD_CONVERSATIONS=%d" % total_unread, flush=True)
    print("ALERTS_WRITTEN=%d" % len(alerts), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
