# ============================================================
# 🔐 A STEAV TOOLS 7777 — LICENSE SERVER
# Deploy FREE on: Render.com / Railway.app
# ============================================================
# pip install flask

from flask import Flask, request, jsonify
import json, os, hashlib, hmac as _hmac, uuid
from datetime import datetime

app = Flask(__name__)

# ── SECRET (same as KeyGen) ──────────────────────────────────
_MASTER = "ASTEAV-2027-MASTER-KEY"
_SALT   = "STEAV_SECRET_V77"
_ADMIN  = os.environ.get("ADMIN_TOKEN", "asteav-admin-7777")  # set in Render env vars

# ── DATABASE (file-based, simple) ────────────────────────────
DB_FILE = "keys.json"

def db_load():
    try:
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "r") as f:
                return json.load(f)
    except: pass
    return {"keys": {}}

def db_save(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

# ── LICENSE ENGINE ────────────────────────────────────────────
def _hash(t):
    return _hmac.new((_MASTER + _SALT).encode(),
                     f"{_MASTER}:{t}".encode(),
                     hashlib.sha256).hexdigest()[:16]

def verify_key_logic(key_str, hwid=""):
    try:
        hx  = key_str.strip()[5:].replace("-", "")
        ver = hx[-8:]
        enc = bytes.fromhex(hx[:-8])
        sc  = (_MASTER * 20)[:len(enc)]
        pl  = bytes(a ^ b for a, b in zip(enc, sc.encode())).decode('utf-8', errors='ignore').split("|")
        if len(pl) < 4:
            return False, {}, "INVALID_FORMAT"
        u, e, d, hw = pl[0], pl[1], pl[2], pl[3]
        if not _hmac.compare_digest(_hash(f"{u}:{e}:{d}:{hw}")[:8], ver.lower()):
            return False, {}, "TAMPERED"
        dl = (datetime.strptime(e, "%Y-%m-%d") - datetime.now()).days
        if dl < 0:
            return False, {"username": u, "expire": e, "days_left": dl, "hwid": hw}, "EXPIRED"
        if hw and hw != "ANY" and hwid and hw != hwid:
            return False, {"username": u, "expire": e, "days_left": dl, "hwid": hw}, "HWID_MISMATCH"
        return True, {"username": u, "expire": e, "days_left": dl, "hwid": hw}, "OK"
    except Exception as ex:
        return False, {}, f"ERROR:{ex}"

# ── ROUTES ───────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "A STEAV LICENSE SERVER", "version": "3.0"}), 200


@app.route("/verify", methods=["POST"])
def verify():
    """
    Called by Tools.exe every launch.
    Body: { "key": "7777-...", "hwid": "ABC123", "app_version": "7777" }
    """
    data  = request.get_json(silent=True) or {}
    key   = data.get("key", "").strip()
    hwid  = data.get("hwid", "").strip()
    ver   = data.get("app_version", "")

    if not key:
        return jsonify({"valid": False, "reason": "NO_KEY"}), 400

    # 1. Verify key math
    ok, info, reason = verify_key_logic(key, hwid)
    if not ok:
        # Log failed attempt
        _log_attempt(key, hwid, False, reason)
        return jsonify({"valid": False, "reason": reason, "info": info}), 200

    # 2. Check server-side revocation (admin can revoke any key)
    db = db_load()
    rec = db["keys"].get(key)
    if rec:
        if rec.get("status") == "Revoked":
            _log_attempt(key, hwid, False, "REVOKED")
            return jsonify({"valid": False, "reason": "REVOKED"}), 200
        # HWID Lock: if first use, bind HWID to key
        if rec.get("hwid") == "ANY" and hwid:
            rec["hwid"]        = hwid
            rec["hwid_locked"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            db_save(db)
            info["hwid"] = hwid
        elif rec.get("hwid") and rec["hwid"] != "ANY" and hwid and rec["hwid"] != hwid:
            _log_attempt(key, hwid, False, "HWID_LOCKED")
            return jsonify({"valid": False, "reason": "HWID_LOCKED",
                            "message": "Key already bound to another PC"}), 200

    # 3. Log success
    _log_attempt(key, hwid, True, "OK")
    return jsonify({"valid": True, "reason": "OK", "info": info}), 200


@app.route("/register", methods=["POST"])
def register():
    """
    Admin registers a key into server DB.
    Body: { "admin_token": "...", "key": "...", "username": "...",
            "days": 30, "hwid": "ANY", "plan": "Standard", "note": "" }
    """
    data = request.get_json(silent=True) or {}
    if data.get("admin_token") != _ADMIN:
        return jsonify({"error": "UNAUTHORIZED"}), 403

    key      = data.get("key", "").strip()
    username = data.get("username", "")
    days     = int(data.get("days", 30))
    hwid     = data.get("hwid", "ANY") or "ANY"
    plan     = data.get("plan", "Standard")
    note     = data.get("note", "")

    if not key:
        return jsonify({"error": "NO_KEY"}), 400

    # Validate key math first
    ok, info, reason = verify_key_logic(key)
    if not ok and reason not in ("EXPIRED",):
        return jsonify({"error": f"INVALID_KEY: {reason}"}), 400

    db = db_load()
    db["keys"][key] = {
        "username": username,
        "days":     days,
        "hwid":     hwid,
        "plan":     plan,
        "note":     note,
        "status":   "Active",
        "created":  datetime.now().strftime("%Y-%m-%d %H:%M"),
        "expire":   info.get("expire", ""),
        "attempts": []
    }
    db_save(db)
    return jsonify({"success": True, "key": key, "registered": username}), 200


@app.route("/revoke", methods=["POST"])
def revoke():
    """
    Admin revokes a key.
    Body: { "admin_token": "...", "key": "7777-..." }
    """
    data = request.get_json(silent=True) or {}
    if data.get("admin_token") != _ADMIN:
        return jsonify({"error": "UNAUTHORIZED"}), 403

    key = data.get("key", "").strip()
    db  = db_load()
    if key not in db["keys"]:
        return jsonify({"error": "KEY_NOT_FOUND"}), 404

    db["keys"][key]["status"]  = "Revoked"
    db["keys"][key]["revoked"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    db_save(db)
    return jsonify({"success": True, "revoked": key}), 200


@app.route("/list", methods=["POST"])
def list_keys():
    """Admin list all keys."""
    data = request.get_json(silent=True) or {}
    if data.get("admin_token") != _ADMIN:
        return jsonify({"error": "UNAUTHORIZED"}), 403

    db = db_load()
    return jsonify({"total": len(db["keys"]), "keys": db["keys"]}), 200


def _log_attempt(key, hwid, success, reason):
    db  = db_load()
    rec = db["keys"].get(key)
    if rec:
        if "attempts" not in rec:
            rec["attempts"] = []
        rec["attempts"].append({
            "time":    datetime.now().strftime("%Y-%m-%d %H:%M"),
            "hwid":    hwid,
            "success": success,
            "reason":  reason
        })
        # Keep last 20 attempts only
        rec["attempts"] = rec["attempts"][-20:]
        db_save(db)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
