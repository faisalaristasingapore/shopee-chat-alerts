#!/usr/bin/env python3
"""One-time Shopee OAuth code exchange for the chat unread poller.

Exchanges the authorization code for access/refresh tokens via
POST /api/v2/auth/token/get, encrypts them with TOKEN_PASSPHRASE and stores
them in tokens.enc (committed by the workflow). Prints no token values.
"""
import argparse
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
TOKEN_GET = "/api/v2/auth/token/get"


def sign(base, key):
    return hmac.new(key.encode(), base.encode(), hashlib.sha256).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", required=True,
                    help="OAuth authorization code (single-use)")
    args = ap.parse_args()
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
    ts = int(time.time())
    q = {"partner_id": pid, "timestamp": ts,
         "sign": sign("%s%s%s" % (pid, TOKEN_GET, ts), pkey)}
    url = HOST + TOKEN_GET + "?" + urllib.parse.urlencode(q)
    body = json.dumps({"partner_id": int(pid), "shop_id": int(shop),
                       "code": args.code}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            payload = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        print("EXCHANGE_FAIL", "http=%s body=%s" % (
            e.code, e.read().decode("utf8", "replace")[:300]), flush=True)
        return 1
    except Exception as e:
        print("EXCHANGE_FAIL", "transport_error=%s" % str(e)[:200],
              flush=True)
        return 1
    if payload.get("error"):
        print("EXCHANGE_FAIL", "error=%r message=%r" % (
            payload.get("error"), payload.get("message")), flush=True)
        return 1
    resp = payload.get("response", payload) if isinstance(payload, dict) else {}
    atok = resp.get("access_token", "") if isinstance(resp, dict) else ""
    rtok = resp.get("refresh_token", "") if isinstance(resp, dict) else ""
    if not atok or not rtok:
        print("EXCHANGE_FAIL: no tokens in response", flush=True)
        return 1
    from cryptography.fernet import Fernet
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(),
                             b"shopee-chat-alerts-v1", 100_000, 32)
    blob = Fernet(base64.urlsafe_b64encode(dk)).encrypt(
        json.dumps({"access_token": atok, "refresh_token": rtok}).encode())
    with open("tokens.enc", "wb") as f:
        f.write(blob)
    print("EXCHANGE_OK", flush=True)
    print("TOKENS_STORED_OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
