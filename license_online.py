# ============================================================
# license_online.py
# DROP this file in same folder as A_Steav_WITH_LICENSE.py
# ============================================================
import hashlib, json, os, threading, time
try:
    import requests
    _REQ_OK = True
except:
    _REQ_OK = False

# ── CONFIG ── ប្តូរ URL នេះបន្ទាប់ deploy ──────────────────
SERVER_URL  = "https://a-steav-tools.onrender.com"   # ← ប្តូរ!
_APP_VER    = "7777"
_TIMEOUT    = 8   # seconds
# ────────────────────────────────────────────────────────────

_cache      = {}          # {key: (valid, ts)}
_CACHE_TTL  = 3600        # 1 hour cache — avoid spam

def verify_online(key: str, hwid: str) -> tuple:
    """
    Verify key against server.
    Returns (valid: bool, reason: str, info: dict)
    Uses cache to avoid calling server every time.
    Falls back to True (offline) if server unreachable.
    """
    if not _REQ_OK:
        return True, "OFFLINE_NO_REQUESTS", {}

    # Check cache
    cache_key = f"{key}:{hwid}"
    if cache_key in _cache:
        val, ts, reason, info = _cache[cache_key]
        if time.time() - ts < _CACHE_TTL:
            return val, reason, info

    try:
        r = requests.post(
            f"{SERVER_URL}/verify",
            json={"key": key, "hwid": hwid, "app_version": _APP_VER},
            timeout=_TIMEOUT
        )
        d = r.json()
        valid  = d.get("valid", False)
        reason = d.get("reason", "UNKNOWN")
        info   = d.get("info", {})
        # Cache result
        _cache[cache_key] = (valid, time.time(), reason, info)
        return valid, reason, info
    except requests.exceptions.ConnectionError:
        # Server offline → allow (offline mode)
        return True, "SERVER_OFFLINE", {}
    except requests.exceptions.Timeout:
        return True, "SERVER_TIMEOUT", {}
    except Exception as ex:
        return True, f"ERROR:{ex}", {}


def revoke_check_async(key: str, hwid: str, on_revoked_callback):
    """
    Background check every 30 min.
    If server says REVOKED → call on_revoked_callback().
    """
    def _worker():
        while True:
            time.sleep(1800)  # 30 minutes
            try:
                valid, reason, _ = verify_online(key, hwid)
                if not valid and reason in ("REVOKED", "HWID_LOCKED", "EXPIRED"):
                    on_revoked_callback(reason)
                    break
            except:
                pass
    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return t
