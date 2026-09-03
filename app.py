from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)

import sqlite3
import bcrypt
import pyotp
import qrcode
import io
import os
import secrets
import re


# ============================================================
# FLASK CONFIGURATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)
)

# Use an absolute path so SQLite works correctly on Render
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "users.db")


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_db():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            two_fa_secret TEXT,
            two_fa_enabled INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


# Initialize database when application starts
init_db()


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # ----------------------------------------------------
        # REQUIRED FIELDS
        # ----------------------------------------------------

        if not name or not email or not password:

            flash(
                "Please fill in all required fields.",
                "danger"
            )

            return redirect(url_for("register"))

        # ----------------------------------------------------
        # EMAIL VALIDATION
        # ----------------------------------------------------

        email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

        if not re.match(email_pattern, email):

            flash(
                "Please enter a valid email address.",
                "danger"
            )

            return redirect(url_for("register"))

        # ----------------------------------------------------
        # PASSWORD CONFIRMATION
        # ----------------------------------------------------

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return redirect(url_for("register"))

        # ----------------------------------------------------
        # PASSWORD LENGTH
        # ----------------------------------------------------

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "danger"
            )

            return redirect(url_for("register"))

        # ----------------------------------------------------
        # CHECK EXISTING USER
        # ----------------------------------------------------

        conn = get_db()

        existing_user = conn.execute(
            """
            SELECT id
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if existing_user:

            conn.close()

            flash(
                "An account with this email already exists.",
                "error"
            )

            return redirect(url_for("register"))

        # ----------------------------------------------------
        # HASH PASSWORD
        # ----------------------------------------------------

        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        # ----------------------------------------------------
        # CREATE USER
        # ----------------------------------------------------

        conn.execute(
            """
            INSERT INTO users
            (
                name,
                email,
                password_hash,
                two_fa_secret,
                two_fa_enabled
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                name,
                email,
                password_hash,
                None,
                0
            )
        )

        conn.commit()
        conn.close()

        flash(
            "Account created successfully. Please log in.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        # ----------------------------------------------------
        # EMPTY FIELDS
        # ----------------------------------------------------

        if not email or not password:

            flash(
                "Please enter your email and password.",
                "danger"
            )

            return redirect(url_for("login"))

        # ----------------------------------------------------
        # FIND USER
        # ----------------------------------------------------

        conn = get_db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        conn.close()

        # ----------------------------------------------------
        # USER NOT FOUND
        # ----------------------------------------------------

        if not user:

            flash(
                "Invalid email or password.",
                "error"
            )

            return redirect(url_for("login"))

        # ----------------------------------------------------
        # CHECK PASSWORD
        # ----------------------------------------------------

        try:

            password_correct = bcrypt.checkpw(
                password.encode("utf-8"),
                user["password_hash"].encode("utf-8")
            )

        except Exception:

            password_correct = False

        # ----------------------------------------------------
        # WRONG PASSWORD
        # ----------------------------------------------------

        if not password_correct:

            flash(
                "Invalid email or password.",
                "error"
            )

            return redirect(url_for("login"))

        # ====================================================
        # 2FA ENABLED
        # ====================================================

        if user["two_fa_enabled"] == 1:

            session.clear()

            session["pending_user_id"] = user["id"]

            return redirect(
                url_for("verify_2fa")
            )

        # ====================================================
        # NORMAL LOGIN
        # ====================================================

        session.clear()

        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["email"] = user["email"]

        flash(
            "Login successful.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template("login.html")


# ============================================================
# SETUP 2FA
# ============================================================

@app.route("/setup-2fa")
def setup_2fa():

    if "user_id" not in session:

        flash(
            "Please login first.",
            "warning"
        )

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    conn = get_db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if not user:

        session.clear()

        flash(
            "User account not found.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    # --------------------------------------------------------
    # ALREADY ENABLED
    # --------------------------------------------------------

    if user["two_fa_enabled"] == 1:

        flash(
            "Two-factor authentication is already enabled.",
            "info"
        )

        return redirect(
            url_for("dashboard")
        )

    # --------------------------------------------------------
    # CREATE SECRET
    # --------------------------------------------------------

    secret = user["two_fa_secret"]

    if not secret:

        secret = pyotp.random_base32()

        conn = get_db()

        conn.execute(
            """
            UPDATE users
            SET two_fa_secret = ?
            WHERE id = ?
            """,
            (
                secret,
                user_id
            )
        )

        conn.commit()
        conn.close()

    # --------------------------------------------------------
    # CREATE TOTP URI
    # --------------------------------------------------------

    totp = pyotp.TOTP(secret)

    uri = totp.provisioning_uri(
        name=user["email"],
        issuer_name="Secure Login System"
    )

    return render_template(
        "setup_2fa.html",
        secret=secret,
        qr_data=uri,
        user=user
    )


# ============================================================
# QR CODE
# ============================================================

@app.route("/qr-code")
def qr_code():

    user_id = session.get("user_id")

    if not user_id:
        user_id = session.get("pending_user_id")

    if not user_id:

        return (
            "Unauthorized. Please login first.",
            401
        )

    conn = get_db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if not user:

        return (
            "User not found.",
            404
        )

    secret = user["two_fa_secret"]

    if not secret:

        return (
            "2FA secret not found.",
            404
        )

    # --------------------------------------------------------
    # CREATE TOTP URI
    # --------------------------------------------------------

    totp = pyotp.TOTP(secret)

    uri = totp.provisioning_uri(
        name=user["email"],
        issuer_name="Secure Login System"
    )

    # --------------------------------------------------------
    # CREATE QR
    # --------------------------------------------------------

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4
    )

    qr.add_data(uri)
    qr.make(fit=True)

    image = qr.make_image()

    # --------------------------------------------------------
    # STORE IMAGE IN MEMORY
    # --------------------------------------------------------

    image_bytes = io.BytesIO()

    image.save(
        image_bytes,
        format="PNG"
    )

    image_bytes.seek(0)

    return send_file(
        image_bytes,
        mimetype="image/png",
        download_name="2fa-qrcode.png"
    )


# ============================================================
# ENABLE 2FA
# ============================================================

@app.route("/enable-2fa", methods=["POST"])
def enable_2fa():

    if "user_id" not in session:

        flash(
            "Please login first.",
            "warning"
        )

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    otp = request.form.get(
        "otp",
        ""
    ).strip()

    # --------------------------------------------------------
    # OTP FORMAT
    # --------------------------------------------------------

    if not otp.isdigit() or len(otp) != 6:

        flash(
            "Please enter a valid 6-digit authentication code.",
            "danger"
        )

        return redirect(
            url_for("setup_2fa")
        )

    # --------------------------------------------------------
    # GET USER
    # --------------------------------------------------------

    conn = get_db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if not user:

        conn.close()

        flash(
            "User account not found.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    secret = user["two_fa_secret"]

    if not secret:

        conn.close()

        flash(
            "2FA secret is missing.",
            "danger"
        )

        return redirect(
            url_for("setup_2fa")
        )

    # --------------------------------------------------------
    # VERIFY OTP
    # --------------------------------------------------------

    totp = pyotp.TOTP(secret)

    if not totp.verify(otp):

        conn.close()

        flash(
            "Invalid authentication code. Please try again.",
            "danger"
        )

        return redirect(
            url_for("setup_2fa")
        )

    # --------------------------------------------------------
    # ENABLE 2FA
    # --------------------------------------------------------

    conn.execute(
        """
        UPDATE users
        SET two_fa_enabled = 1
        WHERE id = ?
        """,
        (user_id,)
    )

    conn.commit()
    conn.close()

    # --------------------------------------------------------
    # SUCCESS MESSAGE
    # --------------------------------------------------------

    flash(
        "Two-factor authentication has been enabled successfully!",
        "success"
    )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# VERIFY 2FA DURING LOGIN
# ============================================================

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():

    # --------------------------------------------------------
    # CHECK PENDING LOGIN
    # --------------------------------------------------------

    if "pending_user_id" not in session:

        flash(
            "Your login session has expired. Please login again.",
            "warning"
        )

        return redirect(
            url_for("login")
        )

    user_id = session["pending_user_id"]

    conn = get_db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if not user:

        session.clear()

        flash(
            "User account not found.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        otp = request.form.get(
            "otp",
            ""
        ).strip()

        # ----------------------------------------------------
        # OTP FORMAT
        # ----------------------------------------------------

        if not otp.isdigit() or len(otp) != 6:

            flash(
                "Please enter a valid 6-digit authentication code.",
                "danger"
            )

            return redirect(
                url_for("verify_2fa")
            )

        secret = user["two_fa_secret"]

        if not secret:

            flash(
                "2FA secret is missing.",
                "danger"
            )

            return redirect(
                url_for("login")
            )

        # ----------------------------------------------------
        # VERIFY OTP
        # ----------------------------------------------------

        totp = pyotp.TOTP(secret)

        if not totp.verify(otp):

            flash(
                "Invalid authentication code. Please try again.",
                "danger"
            )

            return redirect(
                url_for("verify_2fa")
            )

        # ----------------------------------------------------
        # SUCCESSFUL LOGIN
        # ----------------------------------------------------

        session.clear()

        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["email"] = user["email"]

        flash(
            "Two-factor authentication successful.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    # ========================================================
    # GET
    # ========================================================

    return render_template(
        "verify_2fa.html",
        user=user
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        flash(
            "Please login to access the dashboard.",
            "warning"
        )

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    conn = get_db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if not user:

        session.clear()

        flash(
            "User account not found.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "dashboard.html",
        user=user
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out successfully.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    # If 404.html exists, show it.
    # Otherwise return a simple response.
    try:

        return render_template(
            "404.html"
        ), 404

    except Exception:

        return (
            "404 - Page not found.",
            404
        )


@app.errorhandler(500)
def internal_server_error(error):

    # If 500.html exists, show it.
    # Otherwise return a simple response.
    try:

        return render_template(
            "500.html"
        ), 500

    except Exception:

        return (
            "500 - Internal server error.",
            500
        )


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    init_db()

    print("")
    print("====================================================")
    print("              SECURE LOGIN SYSTEM")
    print("====================================================")
    print("")
    print("Server running at:")
    print("http://127.0.0.1:5000")
    print("")
    print("Press CTRL+C to stop the server.")
    print("====================================================")
    print("")

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=True
    )