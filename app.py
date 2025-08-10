
"""
app.py - Full integrated app for MultiGames (Phases 1-5)

Features:
- Firebase Authentication verification for Google sign-in (frontend uses Firebase Web SDK)
- Email/password signup/login (local hashed passwords)
- Admin panel (admin emails configured via ADMIN_EMAILS)
- Safe ZIP upload & extraction to static/games/<slug>
- Publish / Draft workflow
- Embedded iframe play route with CSP
- Stripe Checkout for premium upgrades (demo mode)
- OpenAI-based support endpoint
- SQLite via SQLAlchemy
"""

import os
import io
import zipfile
import shutil
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
    jsonify, send_from_directory, abort, make_response
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# Optional: load .env in dev
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# External services
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
import openai
import stripe

# -------------------------
# Configuration
# -------------------------
BASE_DIR = Path(__file__).resolve().parent
STATIC_FOLDER = BASE_DIR / "static"
GAMES_FOLDER = STATIC_FOLDER / "games"
UPLOAD_TMP = BASE_DIR / "tmp_uploads"

os.makedirs(GAMES_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_TMP, exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_FOLDER), template_folder=str(BASE_DIR / "templates"))
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'game_zone.db'}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", 100 * 1024 * 1024))  # 100MB default

# Admin emails (comma separated)
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()}

# Allowed extensions inside uploaded zip
ALLOWED_ASSET_EXTS = {'.html', '.htm', '.js', '.mjs', '.css', '.json', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.wasm'}

# Stripe & OpenAI config
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID")  # optional, use if you created a price on Stripe
openai_key = os.environ.get("OPENAI_API_KEY")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

if openai_key:
    openai.api_key = openai_key

# -------------------------
# Firebase Admin init
# -------------------------
FIREBASE_SA_PATH = os.environ.get("FIREBASE_SA_PATH", str(BASE_DIR / "firebase_service_account.json"))
if not firebase_admin._apps:
    if not Path(FIREBASE_SA_PATH).exists():
        app.logger.warning("Firebase service account not found at %s — firebase verification will fail.", FIREBASE_SA_PATH)
    else:
        cred = credentials.Certificate(FIREBASE_SA_PATH)
        firebase_admin.initialize_app(cred)

# -------------------------
# DB (SQLAlchemy)
# -------------------------
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(160), nullable=False)
    email = db.Column(db.String(240), unique=True, nullable=False)
    password_hash = db.Column(db.String(300))
    firebase_uid = db.Column(db.String(300), unique=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_premium = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(240), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    description = db.Column(db.Text)
    is_premium = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(30), default="draft")  # draft / published
    upload_path = db.Column(db.String(400))  # relative path under static/games/<slug>/
    thumbnail = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_email = db.Column(db.String(240))
    action = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# -------------------------
# Helpers
# -------------------------
def login_user_session(user: User):
    session['user_id'] = user.id
    session['email'] = user.email
    session['is_admin'] = bool(user.is_admin)
    session.modified = True

def logout_session():
    session.clear()

def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return User.query.get(uid)

def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or not u.is_admin:
            flash("Admin access required", "warning")
            return redirect(url_for("index"))
        return fn(*a, **kw)
    return wrapper

def is_safe_path(base_dir: Path, target: Path):
    try:
        base = base_dir.resolve()
        target_resolved = target.resolve()
        return str(target_resolved).startswith(str(base))
    except Exception:
        return False

def secure_extract_zip(zip_path: Path, dest_dir: Path):
    """
    Validates that zip contains only allowed asset extensions and no path traversal,
    then extracts to dest_dir.
    """
    with zipfile.ZipFile(str(zip_path), 'r') as z:
        for info in z.infolist():
            # skip directories
            if info.is_dir():
                continue
            # normalize name
            filename = info.filename
            # Prevent absolute paths
            if os.path.isabs(filename):
                raise ValueError("Absolute paths are not allowed in ZIP")
            # Prevent path traversal
            normalized = os.path.normpath(filename)
            if normalized.startswith(".."):
                raise ValueError("Path traversal detected in ZIP")
            _, ext = os.path.splitext(filename.lower())
            # allow files without extension? usually index.html has extension
            if ext and ext not in ALLOWED_ASSET_EXTS:
                raise ValueError(f"Forbidden file type in zip: {ext}")
        # all checks passed -> extract
        z.extractall(str(dest_dir))

def log_admin_action(admin_email: str, action: str):
    entry = AdminLog(admin_email=admin_email, action=action)
    db.session.add(entry)
    db.session.commit()

def verify_firebase_token(id_token: str):
    """Returns decoded token dict or raises exception."""
    if not id_token:
        raise ValueError("Missing Firebase token")
    # firebase_admin must be initialized
    if not firebase_admin._apps:
        raise RuntimeError("Firebase Admin SDK not initialized on server")
    decoded = firebase_auth.verify_id_token(id_token)
    return decoded

def get_logged_in_email_from_cookie():
    """Frontend should store idToken in cookie 'firebase_token' after login; fallback uses session."""
    id_token = request.cookies.get("firebase_token")
    if id_token:
        try:
            decoded = verify_firebase_token(id_token)
            return decoded.get("email")
        except Exception:
            return None
    # fallback to session
    return session.get("email")

# -------------------------
# Routes - Auth & Home
# -------------------------
@app.route("/")
def index():
    user = current_user()
    games = Game.query.filter_by(status="published").all()
    return render_template("index.html", user=user, games=games, stripe_pub_key=STRIPE_PUBLISHABLE_KEY)

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form.get("username", "").strip() or "Player"
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not email or not password:
        flash("Email and password required", "error")
        return redirect(url_for("index"))
    if User.query.filter_by(email=email).first():
        flash("Email already registered", "error")
        return redirect(url_for("index"))
    pw_hash = generate_password_hash(password)
    is_admin = email in ADMIN_EMAILS
    user = User(username=username, email=email, password_hash=pw_hash, is_admin=is_admin)
    db.session.add(user)
    db.session.commit()
    login_user_session(user)
    flash("Account created and logged in", "success")
    return redirect(url_for("index"))

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    user = User.query.filter_by(email=email).first()
    if user and user.password_hash and check_password_hash(user.password_hash, password):
        login_user_session(user)
        flash("Logged in", "success")
        return redirect(url_for("index"))
    flash("Invalid credentials", "error")
    return redirect(url_for("index"))

@app.route("/firebase_login", methods=["POST"])
def firebase_login():
    """
    Expects JSON { "idToken": "<firebase id token>" }
    Verifies token server-side, creates or updates local user record, and creates session.
    """
    payload = request.get_json() or {}
    id_token = payload.get("idToken")
    if not id_token:
        return jsonify({"error": "Missing idToken"}), 400
    try:
        decoded = verify_firebase_token(id_token)
    except Exception as e:
        return jsonify({"error": f"Token verify failed: {e}"}), 400

    email = decoded.get("email")
    name = decoded.get("name") or (email.split("@")[0] if email else "Player")
    uid = decoded.get("uid")

    if not email:
        return jsonify({"error": "Token has no email"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(username=name, email=email, firebase_uid=uid, is_admin=(email in ADMIN_EMAILS))
        db.session.add(user)
        db.session.commit()
    else:
        # attach firebase uid if missing
        if not user.firebase_uid:
            user.firebase_uid = uid
            db.session.commit()

    # log user in (create server session)
    login_user_session(user)

    # Return where frontend should redirect
    redirect_to = "/admin" if user.is_admin else "/"
    return jsonify({"redirect": redirect_to})

@app.route("/logout")
def logout():
    logout_session()
    # Also clear firebase_token cookie on client; server can't remove client cookie reliably here,
    # but we give a minimal response.
    resp = redirect(url_for("index"))
    resp.set_cookie("firebase_token", "", expires=0)
    return resp

# Password reset (test-mode)
@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    email = request.form.get("email", "").strip().lower()
    if not email:
        flash("Email required", "error")
        return redirect(url_for("index"))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("If the email exists, a reset was sent (test mode)", "info")
        return redirect(url_for("index"))
    reset_link = f"{request.url_root}reset_password/{user.id}"
    # In production you would send this by email; here we print it for demo/test.
    app.logger.info("[TEST MODE] Password reset link for %s: %s", email, reset_link)
    flash("Password reset link generated (check server logs in test mode).", "info")
    return redirect(url_for("index"))

@app.route("/reset_password/<int:user_id>", methods=["GET", "POST"])
def reset_password(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        new_pw = request.form.get("password", "")
        if not new_pw:
            flash("Password required", "error")
            return redirect(request.url)
        user.password_hash = generate_password_hash(new_pw)
        db.session.commit()
        flash("Password updated; please log in.", "success")
        return redirect(url_for("index"))
    return render_template("reset_password.html", user=user)

# -------------------------
# Admin routes - Games & Users
# -------------------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    user = current_user()
    games = Game.query.order_by(Game.created_at.desc()).all()
    logs = AdminLog.query.order_by(AdminLog.created_at.desc()).limit(40).all()
    return render_template("admin_panel.html", user=user, games=games, logs=logs)

@app.route("/admin/upload", methods=["POST"])
@admin_required
def admin_upload():
    user = current_user()
    title = request.form.get("title", "").strip()
    slug_raw = request.form.get("slug", "").strip()
    slug = secure_filename(slug_raw) if slug_raw else secure_filename(title.lower().replace(" ", "-"))
    description = request.form.get("description", "")
    is_premium = bool(request.form.get("is_premium"))
    publish_now = bool(request.form.get("publish_now"))

    file = request.files.get("zipfile")
    if not file:
        flash("No file uploaded", "error")
        return redirect(url_for("admin_dashboard"))

    if not file.filename.lower().endswith(".zip"):
        flash("Only .zip files are accepted", "error")
        return redirect(url_for("admin_dashboard"))

    # save temp zip
    ts = int(datetime.utcnow().timestamp())
    tmp_name = f"{ts}_{secure_filename(file.filename)}"
    tmp_path = UPLOAD_TMP / tmp_name
    file.save(str(tmp_path))

    # destination folder for extracted game
    dest_dir = GAMES_FOLDER / slug
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # validate & extract
    try:
        secure_extract_zip(tmp_path, dest_dir)
    except Exception as e:
        # cleanup
        shutil.rmtree(dest_dir, ignore_errors=True)
        tmp_path.unlink(missing_ok=True)
        flash(f"Upload failed: {e}", "error")
        return redirect(url_for("admin_dashboard"))

    # remove tmp zip
    tmp_path.unlink(missing_ok=True)

    # create or update DB record
    g = Game.query.filter_by(slug=slug).first()
    if not g:
        g = Game(title=title or slug, slug=slug, description=description, is_premium=is_premium)
    else:
        g.title = title or g.title
        g.description = description
        g.is_premium = is_premium

    g.upload_path = f"games/{slug}"
    g.status = "published" if publish_now else "draft"
    db.session.add(g)
    db.session.commit()

    log_admin_action(user.email, f"Uploaded game '{g.title}' slug={g.slug} status={g.status}")
    flash("Game uploaded successfully", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/publish/<int:game_id>", methods=["POST"])
@admin_required
def admin_publish(game_id):
    user = current_user()
    g = Game.query.get_or_404(game_id)
    g.status = "published"
    db.session.commit()
    log_admin_action(user.email, f"Published game '{g.title}'")
    flash("Game published", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete/<int:game_id>", methods=["POST"])
@admin_required
def admin_delete(game_id):
    user = current_user()
    g = Game.query.get_or_404(game_id)
    # remove files
    folder = GAMES_FOLDER / g.slug
    try:
        if folder.exists():
            shutil.rmtree(folder)
    except Exception:
        app.logger.exception("Failed to delete game folder")
    db.session.delete(g)
    db.session.commit()
    log_admin_action(user.email, f"Deleted game '{g.title}'")
    flash("Game deleted", "info")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/users")
@admin_required
def admin_users():
    user = current_user()
    users = User.query.order_by(User.created_at.desc()).all()
    logs = AdminLog.query.order_by(AdminLog.created_at.desc()).limit(40).all()
    return render_template("admin_users.html", user=user, users=users, logs=logs)

@app.route("/admin/users/<int:user_id>/toggle_premium", methods=["POST"])
@admin_required
def admin_toggle_premium(user_id):
    admin = current_user()
    target = User.query.get_or_404(user_id)
    target.is_premium = not target.is_premium
    db.session.commit()
    log_admin_action(admin.email, f"Toggled premium for {target.email} -> {target.is_premium}")
    flash("User premium status updated.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    admin = current_user()
    target = User.query.get_or_404(user_id)
    db.session.delete(target)
    db.session.commit()
    log_admin_action(admin.email, f"Deleted user {target.email}")
    flash("User deleted.", "info")
    return redirect(url_for("admin_users"))

# -------------------------
# Serve game assets safely
# -------------------------
@app.route("/games_assets/<game_slug>/<path:filename>")
def serve_game_asset(game_slug, filename):
    # sanitize slug and prevent traversal
    safe_slug = secure_filename(game_slug)
    folder = GAMES_FOLDER / safe_slug
    if not folder.exists():
        return abort(404)
    # normalize path
    normalized = os.path.normpath(filename)
    if normalized.startswith(".."):
        return abort(404)
    full_path = folder / normalized
    if not is_safe_path(GAMES_FOLDER, full_path):
        return abort(404)
    if not full_path.exists():
        return abort(404)
    return send_from_directory(str(folder), str(normalized))

# Play embed page with CSP
@app.route("/game/<slug>/play")
def play_game(slug):
    g = Game.query.filter_by(slug=slug, status="published").first_or_404()
    folder = GAMES_FOLDER / g.slug
    index_file = None
    for name in ("index.html", "index.htm"):
        if (folder / name).exists():
            index_file = name
            break
    if not index_file:
        abort(404)
    play_url = url_for("serve_game_asset", game_slug=g.slug, filename=index_file)
    resp = make_response(render_template("play_embed.html", game=g, play_url=play_url))
    # CSP header to restrict where content can load from (may need relaxation depending on games)
    resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    return resp

# -------------------------
# Stripe / Premium upgrade
# -------------------------
@app.route("/upgrade")
def upgrade():
    email = get_logged_in_email_from_cookie() or session.get("email")
    if not email:
        flash("Please log in to upgrade", "warning")
        return redirect(url_for("index"))
    return render_template("premium.html", stripe_pub_key=STRIPE_PUBLISHABLE_KEY)

@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    email = get_logged_in_email_from_cookie() or session.get("email")
    if not email:
        return jsonify({"error": "Not logged in"}), 403

    # If user has a Stripe Price defined by env, use it; else create inline price_data
    if STRIPE_PRICE_ID:
        line_items = [{"price": STRIPE_PRICE_ID, "quantity": 1}]
    else:
        # example one-time purchase of $5.00
        line_items = [{
            "price_data": {
                "currency": "usd",
                "unit_amount": 500,
                "product_data": {"name": "Premium Membership (One-time demo)"},
            },
            "quantity": 1
        }]

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=line_items,
            mode="payment",
            success_url=url_for("payment_success", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("payment_cancel", _external=True),
            customer_email=email  # prefill email
        )
    except Exception as e:
        app.logger.exception("Stripe session create failed")
        return jsonify({"error": str(e)}), 500

    return jsonify({"id": checkout_session.id})

@app.route("/payment-success")
def payment_success():
    email = get_logged_in_email_from_cookie() or session.get("email")
    if email:
        # mark local user premium
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_premium = True
            db.session.commit()
    return render_template("success.html")

@app.route("/payment-cancel")
def payment_cancel():
    return render_template("cancel.html")

# -------------------------
# Support (OpenAI)
# -------------------------
@app.route("/support")
def support():
    # optionally require login: add decorator
    return render_template("support.html")

@app.route("/api/support", methods=["POST"])
def api_support():
    if not openai_key:
        return jsonify({"error": "AI support not configured"}), 500
    data = request.get_json() or {}
    user_message = (data.get("message") or "").strip()
    if not user_message:
        return jsonify({"error": "No message provided"}), 400

    system_prompt = (
        "You are GameZone Support Bot. Be concise, helpful, and polite. "
        "Give step-by-step troubleshooting for technical issues with HTML5 games, account management, and payments. "
        "If the user asks for confidential actions, instruct them to use the site or contact admin. "
    )

    try:
        # Use chat completion with gpt-3.5-turbo as a stable default
        resp = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            max_tokens=600,
            temperature=0.2,
        )
        reply = resp["choices"][0]["message"]["content"].strip()
        return jsonify({"reply": reply})
    except Exception as e:
        app.logger.exception("OpenAI call failed")
        return jsonify({"error": "AI support temporarily unavailable", "detail": str(e)}), 500

# -------------------------
# Misc: play route for game_id (older style)
# -------------------------
@app.route("/play/<int:game_id>")
def play_game_by_id(game_id):
    g = Game.query.get_or_404(game_id)
    if g.is_premium:
        # check premium status
        email = get_logged_in_email_from_cookie() or session.get("email")
        if not email:
            return "Premium only — please log in & upgrade.", 403
        user = User.query.filter_by(email=email).first()
        if not user or not user.is_premium:
            return "Upgrade to premium to play this game.", 403

    folder = GAMES_FOLDER / g.slug
    idx = None
    for n in ("index.html", "index.htm"):
        if (folder / n).exists():
            idx = n
            break
    if not idx:
        abort(404)
    play_url = url_for("serve_game_asset", game_slug=g.slug, filename=idx)
    resp = make_response(render_template("play_embed.html", game=g, play_url=play_url))
    resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    return resp

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    # ensure folders exist
    GAMES_FOLDER.mkdir(parents=True, exist_ok=True)
    UPLOAD_TMP.mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", debug=True)
