"""
WallDrop – Flask Backend
========================
Moves all secrets server-side so they are never exposed to the browser.

Endpoints
---------
POST /api/login              – admin or user login
POST /api/signup             – register new user
POST /api/logout             – clear session
GET  /api/me                 – current session user
GET  /api/wallpapers         – list wallpapers
POST /api/wallpapers         – add wallpaper (admin only)
DELETE /api/wallpapers/<id>  – delete wallpaper (admin only)
POST /api/upload/github      – upload file → GitHub (admin only)
POST /api/upload/r2          – upload file → Cloudflare R2 (admin only)
DELETE /api/delete/github    – delete file from GitHub (admin only)
DELETE /api/delete/r2        – delete file from R2 (admin only)
POST /api/github/push        – push walldrop-db.json to GitHub DB repo
GET  /api/github/pull        – pull walldrop-db.json from GitHub DB repo
POST /api/favourites         – toggle favourite (logged-in users)
POST /api/ai/analyse         – proxy AI vision call (hides API key)
GET  /                       – serve index.html
"""

import os, json, base64, hashlib, secrets, time, requests
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory, abort

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET")
if not app.secret_key:
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError(
            "FLASK_SECRET environment variable is not set. "
            "Set a fixed secret so sessions survive server restarts."
        )
    # Development fallback — regenerates on restart (sessions lost), but safe for local use
    import warnings
    app.secret_key = secrets.token_hex(32)
    warnings.warn(
        "FLASK_SECRET not set — using a random secret key. "
        "All sessions will be invalidated on server restart. "
        "Set FLASK_SECRET for persistent sessions.",
        stacklevel=1,
    )

# ──────────────────────────────────────────────────────────────────────────────
# ★  ALL SECRETS LIVE HERE — never sent to the browser  ★
# Set via environment variables (recommended) or fill in directly for local dev.
# ──────────────────────────────────────────────────────────────────────────────
ADMIN_EMAIL   = os.environ.get("ADMIN_EMAIL",   "admin@walldrop.nf.gd")
ADMIN_PASS    = os.environ.get("ADMIN_PASS")
if not ADMIN_PASS:
    raise RuntimeError(
        "ADMIN_PASS environment variable is not set. "
        "Set it before starting the server to prevent using a default credential."
    )

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "YOUR_GOOGLE_CLIENT_ID")

# GitHub image storage
GITHUB_TOKEN  = os.environ.get("GITHUB_TOKEN",  "")
GITHUB_USER   = os.environ.get("GITHUB_USER",   "")
GITHUB_REPO   = os.environ.get("GITHUB_REPO",   "")
GITHUB_BRANCH = os.environ.get("GITHUB_BRANCH", "main")
GITHUB_FOLDER = os.environ.get("GITHUB_FOLDER", "wallpapers")

# GitHub DB repo (for walldrop-db.json persistence)
GH_DB_TOKEN  = os.environ.get("GH_DB_TOKEN",  GITHUB_TOKEN)
GH_DB_USER   = os.environ.get("GH_DB_USER",   GITHUB_USER)
GH_DB_REPO   = os.environ.get("GH_DB_REPO",   "")
GH_DB_BRANCH = os.environ.get("GH_DB_BRANCH", "main")
GH_DB_FILE   = "walldrop-db.json"

# Cloudflare R2
R2_WORKER_URL       = os.environ.get("R2_WORKER_URL",       "")
R2_BUCKET_PUBLIC_URL= os.environ.get("R2_BUCKET_PUBLIC_URL","")
R2_AUTH_TOKEN       = os.environ.get("R2_AUTH_TOKEN",       "")

# AI vision
GEMINI_API_KEY    = os.environ.get("GEMINI_API_KEY",    "")
OPENROUTER_API_KEY= os.environ.get("OPENROUTER_API_KEY","")

# ──────────────────────────────────────────────────────────────────────────────
# Simple flat-file "database" (JSON on disk).
# For production swap this out for SQLite / PostgreSQL.
# ──────────────────────────────────────────────────────────────────────────────
DB_FILE = os.path.join(os.path.dirname(__file__), "walldrop_data.json")

DEFAULT_WALLS = [
    {"id":"d1","src":"https://images.unsplash.com/photo-1518623489648-a173ef7824f3?w=1400&q=85","thumb":"https://images.unsplash.com/photo-1518623489648-a173ef7824f3?w=800&q=80","cat":"nature","tag":"Nature","title":"Forest Light","isDefault":True},
    {"id":"d2","src":"https://images.unsplash.com/photo-1462331940025-496dfbfc7564?w=1400&q=85","thumb":"https://images.unsplash.com/photo-1462331940025-496dfbfc7564?w=800&q=80","cat":"space","tag":"Space","title":"Galaxy","isDefault":True},
    {"id":"d3","src":"https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=1400&q=85","thumb":"https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=800&q=80","cat":"nature","tag":"Nature","title":"Alpine Peaks","isDefault":True},
    {"id":"d4","src":"https://images.unsplash.com/photo-1579546929518-9e396f3cc809?w=1400&q=85","thumb":"https://images.unsplash.com/photo-1579546929518-9e396f3cc809?w=800&q=80","cat":"abstract","tag":"Abstract","title":"Color Gradient","isDefault":True},
    {"id":"d5","src":"https://images.unsplash.com/photo-1477959858617-67f85cf4f1df?w=1400&q=85","thumb":"https://images.unsplash.com/photo-1477959858617-67f85cf4f1df?w=800&q=80","cat":"city","tag":"City","title":"City Skyline","isDefault":True},
    {"id":"d6","src":"https://images.unsplash.com/photo-1519681393784-d120267933ba?w=1400&q=85","thumb":"https://images.unsplash.com/photo-1519681393784-d120267933ba?w=800&q=80","cat":"nature","tag":"Nature","title":"Snowy Mountains","isDefault":True},
    {"id":"d7","src":"https://images.unsplash.com/photo-1511300636408-a63a89df3482?w=1400&q=85","thumb":"https://images.unsplash.com/photo-1511300636408-a63a89df3482?w=800&q=80","cat":"minimal","tag":"Minimal","title":"Minimalist","isDefault":True},
    {"id":"d8","src":"https://images.unsplash.com/photo-1534796636912-3b95b3ab5986?w=1400&q=85","thumb":"https://images.unsplash.com/photo-1534796636912-3b95b3ab5986?w=800&q=80","cat":"space","tag":"Space","title":"Deep Space","isDefault":True},
    {"id":"d9","src":"https://images.unsplash.com/photo-1497366216548-37526070297c?w=1400&q=85","thumb":"https://images.unsplash.com/photo-1497366216548-37526070297c?w=800&q=80","cat":"city","tag":"City","title":"Architecture","isDefault":True},
]

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"wallpapers": list(DEFAULT_WALLS), "users": []}

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

def hash_pass(p):
    return "h_" + hashlib.sha256(p.encode()).hexdigest()

# ──────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ──────────────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

# ──────────────────────────────────────────────────────────────────────────────
# Auth routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    # Admin login
    if email == ADMIN_EMAIL.lower() and password == ADMIN_PASS:
        session["user"] = {"email": email, "fname": "Admin", "is_admin": True}
        session["is_admin"] = True
        return jsonify({"ok": True, "is_admin": True, "user": {"fname": "Admin", "email": email}})

    # Regular user login
    db = load_db()
    user = next((u for u in db["users"] if u.get("email","").lower() == email
                 and u.get("passwordHash") == hash_pass(password)), None)
    if not user:
        return jsonify({"error": "Incorrect email or password"}), 401

    safe = {k: user[k] for k in ("id","fname","lname","email","provider","picture","favs","createdAt") if k in user}
    session["user"] = safe
    session["is_admin"] = False
    return jsonify({"ok": True, "is_admin": False, "user": safe})

@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.json or {}
    fname  = (data.get("fname") or "").strip()
    lname  = (data.get("lname") or "").strip()
    email  = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not fname or not email or len(password) < 8:
        return jsonify({"error": "Invalid data"}), 400

    db = load_db()
    if any(u.get("email","").lower() == email for u in db["users"]):
        return jsonify({"error": "Email already registered"}), 409

    user = {
        "id": "e_" + str(int(time.time() * 1000)),
        "fname": fname, "lname": lname, "email": email,
        "passwordHash": hash_pass(password),
        "provider": "email",
        "createdAt": int(time.time() * 1000),
        "favs": []
    }
    db["users"].append(user)
    save_db(db)

    safe = {k: user[k] for k in ("id","fname","lname","email","provider","createdAt","favs") if k in user}
    session["user"] = safe
    session["is_admin"] = False
    return jsonify({"ok": True, "user": safe})

@app.route("/api/google-login", methods=["POST"])
def api_google_login():
    """Verify Google JWT on the server using Google's tokeninfo endpoint."""
    data = request.json or {}
    credential = data.get("credential", "")
    if not credential:
        return jsonify({"error": "Missing credential"}), 400

    # Verify with Google
    resp = requests.get(
        "https://oauth2.googleapis.com/tokeninfo",
        params={"id_token": credential}, timeout=8
    )
    if not resp.ok:
        return jsonify({"error": "Invalid Google token"}), 401

    payload = resp.json()
    if GOOGLE_CLIENT_ID == "YOUR_GOOGLE_CLIENT_ID":
        return jsonify({"error": "Google login is not configured on this server"}), 503
    if payload.get("aud") != GOOGLE_CLIENT_ID:
        return jsonify({"error": "Token audience mismatch"}), 401

    db = load_db()
    g_email = payload.get("email", "").lower()
    user = {
        "id": "g_" + payload.get("sub", ""),
        "fname": payload.get("given_name") or payload.get("name","").split()[0],
        "lname": payload.get("family_name", ""),
        "email": g_email,
        "picture": payload.get("picture", ""),
        "provider": "google",
        "createdAt": int(time.time() * 1000),
        "favs": []
    }
    idx = next((i for i, u in enumerate(db["users"]) if u.get("email","").lower() == g_email), -1)
    if idx >= 0:
        db["users"][idx] = {**db["users"][idx], **user, "createdAt": db["users"][idx].get("createdAt", user["createdAt"])}
        user = db["users"][idx]
    else:
        db["users"].append(user)
    save_db(db)

    safe = {k: user[k] for k in ("id","fname","lname","email","provider","picture","favs","createdAt") if k in user}
    session["user"] = safe
    session["is_admin"] = False
    return jsonify({"ok": True, "user": safe})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/me")
def api_me():
    user = session.get("user")
    if not user:
        return jsonify({"user": None, "is_admin": False})
    return jsonify({"user": user, "is_admin": session.get("is_admin", False)})

# ──────────────────────────────────────────────────────────────────────────────
# Wallpapers
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/wallpapers", methods=["GET"])
def api_get_wallpapers():
    db = load_db()
    return jsonify({"wallpapers": db["wallpapers"]})

@app.route("/api/wallpapers", methods=["POST"])
@admin_required
def api_add_wallpaper():
    data = request.json or {}
    db = load_db()
    wall = {
        "id": "w_" + str(int(time.time() * 1000)),
        "src": data.get("src", ""),
        "thumb": data.get("thumb") or data.get("src", ""),
        "cat": data.get("cat", "other"),
        "tag": data.get("tag") or data.get("cat", "other").capitalize(),
        "title": data.get("title", ""),
        "desc": data.get("desc", ""),
        "createdAt": int(time.time() * 1000)
    }
    db["wallpapers"].append(wall)
    save_db(db)
    return jsonify({"ok": True, "wallpaper": wall})

@app.route("/api/wallpapers/<wall_id>", methods=["DELETE"])
@admin_required
def api_delete_wallpaper(wall_id):
    db = load_db()
    db["wallpapers"] = [w for w in db["wallpapers"] if w.get("id") != wall_id]
    save_db(db)
    return jsonify({"ok": True})

# ──────────────────────────────────────────────────────────────────────────────
# GitHub image storage (proxy — token never leaves server)
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/upload/github", methods=["POST"])
@admin_required
def api_upload_github():
    if not GITHUB_TOKEN or not GITHUB_USER or not GITHUB_REPO:
        return jsonify({"error": "GitHub not configured on server"}), 503

    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file provided"}), 400

    ext  = (file.filename or "img.jpg").rsplit(".", 1)[-1].lower()
    name = f"{int(time.time()*1000)}-{secrets.token_hex(4)}.{ext}"
    path = f"{GITHUB_FOLDER}/{name}"
    api_url = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/contents/{path}"

    b64 = base64.b64encode(file.read()).decode()
    resp = requests.put(api_url, json={
        "message": f"Upload wallpaper: {name}",
        "branch": GITHUB_BRANCH,
        "content": b64,
    }, headers={
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }, timeout=30)

    if not resp.ok:
        return jsonify({"error": f"GitHub error {resp.status_code}"}), 502

    cdn_url = f"https://cdn.jsdelivr.net/gh/{GITHUB_USER}/{GITHUB_REPO}@{GITHUB_BRANCH}/{path}"
    return jsonify({"ok": True, "url": cdn_url})

@app.route("/api/delete/github", methods=["DELETE"])
@admin_required
def api_delete_github():
    if not GITHUB_TOKEN:
        return jsonify({"error": "GitHub not configured"}), 503
    data = request.json or {}
    cdn_url = data.get("url", "")
    prefix = f"https://cdn.jsdelivr.net/gh/{GITHUB_USER}/{GITHUB_REPO}@{GITHUB_BRANCH}/"
    if not cdn_url.startswith(prefix):
        return jsonify({"error": "Not a managed GitHub URL"}), 400
    file_path = cdn_url[len(prefix):]
    api_url = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/contents/{file_path}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    info = requests.get(api_url, headers=headers, timeout=15)
    if not info.ok:
        return jsonify({"error": "File not found on GitHub"}), 404
    sha = info.json().get("sha")
    resp = requests.delete(api_url, json={
        "message": f"Delete wallpaper: {file_path}", "sha": sha, "branch": GITHUB_BRANCH
    }, headers={**headers, "Content-Type": "application/json"}, timeout=15)
    return jsonify({"ok": resp.ok})

# ──────────────────────────────────────────────────────────────────────────────
# Cloudflare R2 (proxy — auth token never leaves server)
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/upload/r2", methods=["POST"])
@admin_required
def api_upload_r2():
    if not R2_WORKER_URL:
        return jsonify({"error": "R2 not configured on server"}), 503
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file"}), 400
    ext = (file.filename or "img.jpg").rsplit(".", 1)[-1].lower()
    key = f"walldrop/{int(time.time()*1000)}-{secrets.token_hex(4)}.{ext}"
    endpoint = f"{R2_WORKER_URL}/upload/{requests.utils.quote(key, safe='')}"
    headers = {"Content-Type": file.content_type or "image/jpeg"}
    if R2_AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {R2_AUTH_TOKEN}"
    resp = requests.put(endpoint, data=file.read(), headers=headers, timeout=30)
    if not resp.ok:
        return jsonify({"error": f"R2 error {resp.status_code}"}), 502
    public_url = f"{R2_BUCKET_PUBLIC_URL.rstrip('/')}/{key}"
    return jsonify({"ok": True, "url": public_url})

@app.route("/api/delete/r2", methods=["DELETE"])
@admin_required
def api_delete_r2():
    if not R2_WORKER_URL:
        return jsonify({"error": "R2 not configured"}), 503
    data = request.json or {}
    url = data.get("url", "")
    base = R2_BUCKET_PUBLIC_URL.rstrip("/") + "/"
    if not url.startswith(base):
        return jsonify({"error": "Not a managed R2 URL"}), 400
    key = url[len(base):]
    endpoint = f"{R2_WORKER_URL}/delete/{requests.utils.quote(key, safe='')}"
    headers = {}
    if R2_AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {R2_AUTH_TOKEN}"
    resp = requests.delete(endpoint, headers=headers, timeout=15)
    return jsonify({"ok": resp.ok})

# ──────────────────────────────────────────────────────────────────────────────
# GitHub DB (walldrop-db.json persistence)
# ──────────────────────────────────────────────────────────────────────────────
def gh_db_enabled():
    return bool(GH_DB_TOKEN and GH_DB_USER and GH_DB_REPO)

def gh_db_headers():
    return {
        "Authorization": f"Bearer {GH_DB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

@app.route("/api/github/push", methods=["POST"])
@admin_required
def api_github_push():
    if not gh_db_enabled():
        return jsonify({"error": "GitHub DB not configured"}), 503
    db = load_db()
    db["updatedAt"] = int(time.time() * 1000)
    content = base64.b64encode(json.dumps(db, indent=2).encode()).decode()
    api_url = f"https://api.github.com/repos/{GH_DB_USER}/{GH_DB_REPO}/contents/{GH_DB_FILE}"
    # Get existing SHA if file exists
    sha = None
    existing = requests.get(api_url, headers=gh_db_headers(), timeout=10)
    if existing.ok:
        sha = existing.json().get("sha")
    body = {"message": "WallDrop DB update", "branch": GH_DB_BRANCH, "content": content}
    if sha:
        body["sha"] = sha
    resp = requests.put(api_url, json=body, headers=gh_db_headers(), timeout=20)
    if resp.ok:
        return jsonify({"ok": True, "wallpapers": len(db["wallpapers"]), "users": len(db["users"])})
    return jsonify({"error": f"Push failed: {resp.status_code}"}), 502

@app.route("/api/github/pull", methods=["GET"])
@admin_required
def api_github_pull():
    if not gh_db_enabled():
        return jsonify({"error": "GitHub DB not configured"}), 503
    raw_url = f"https://raw.githubusercontent.com/{GH_DB_USER}/{GH_DB_REPO}/{GH_DB_BRANCH}/{GH_DB_FILE}"
    resp = requests.get(raw_url, params={"cb": int(time.time())}, timeout=15)
    if not resp.ok:
        return jsonify({"error": f"Could not fetch DB ({resp.status_code})"}), 502
    remote_db = resp.json()
    if not remote_db.get("wallpapers"):
        return jsonify({"error": "Invalid DB file"}), 502
    save_db(remote_db)
    return jsonify({"ok": True, "wallpapers": len(remote_db["wallpapers"]), "users": len(remote_db.get("users", []))})

# ──────────────────────────────────────────────────────────────────────────────
# Users & favourites
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/users")
@admin_required
def api_users():
    db = load_db()
    # Strip passwords before sending
    safe = [{k: u[k] for k in u if k != "passwordHash"} for u in db["users"]]
    return jsonify({"users": safe})

@app.route("/api/favourites", methods=["POST"])
@login_required
def api_toggle_fav():
    data = request.json or {}
    wall_id = data.get("wallId")
    if not wall_id:
        return jsonify({"error": "Missing wallId"}), 400
    # Admins don't have a persistent user record — favouriting is a user-only feature
    if session.get("is_admin"):
        return jsonify({"error": "Admin accounts do not support favourites"}), 403
    db = load_db()
    uid = session["user"].get("id")
    if not uid:
        return jsonify({"error": "User session is missing an id"}), 400
    user = next((u for u in db["users"] if u.get("id") == uid), None)
    if not user:
        return jsonify({"error": "User not found"}), 404
    favs = user.get("favs", [])
    if wall_id in favs:
        favs.remove(wall_id)
        action = "removed"
    else:
        favs.append(wall_id)
        action = "added"
    user["favs"] = favs
    save_db(db)
    session["user"] = {**session["user"], "favs": favs}
    return jsonify({"ok": True, "action": action, "favs": favs})

# ──────────────────────────────────────────────────────────────────────────────
# AI Vision proxy (keeps API keys server-side)
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/ai/analyse", methods=["POST"])
@admin_required
def api_ai_analyse():
    data = request.json or {}
    provider = data.get("provider", "gemini")
    image_b64 = data.get("imageBase64", "")
    mime = data.get("mimeType", "image/jpeg")
    prompt = data.get("prompt", "Analyse this wallpaper. Return JSON: {title, category, description}")

    if provider == "gemini":
        if not GEMINI_API_KEY:
            return jsonify({"error": "Gemini API key not configured on server"}), 503
        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}",
            json={"contents": [{"parts": [
                {"text": prompt},
                {"inline_data": {"mime_type": mime, "data": image_b64}}
            ]}]},
            timeout=30
        )
        if not resp.ok:
            return jsonify({"error": f"Gemini error {resp.status_code}"}), 502
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        return jsonify({"ok": True, "result": text})

    elif provider == "openrouter":
        if not OPENROUTER_API_KEY:
            return jsonify({"error": "OpenRouter API key not configured on server"}), 503
        resp = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            json={"model": "google/gemini-flash-1.5", "messages": [{"role": "user", "content": [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{image_b64}"}}
            ]}]},
            headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"},
            timeout=30
        )
        if not resp.ok:
            return jsonify({"error": f"OpenRouter error {resp.status_code}"}), 502
        text = resp.json()["choices"][0]["message"]["content"]
        return jsonify({"ok": True, "result": text})

    return jsonify({"error": "Unknown provider"}), 400

# ──────────────────────────────────────────────────────────────────────────────
# Serve frontend
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("templates", "index.html")

@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)

# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n🚀 WallDrop Flask backend starting...")
    print(f"   Admin email : {ADMIN_EMAIL}")
    print(f"   GitHub user : {GITHUB_USER or '(not set)'}")
    print(f"   R2 Worker   : {R2_WORKER_URL or '(not set)'}")
    print(f"   DB file     : {DB_FILE}\n")
    app.run(debug=True, port=8080)
