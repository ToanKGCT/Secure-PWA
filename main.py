from flask import Flask, render_template, request, redirect, session, url_for
from flask_wtf.csrf import CSRFProtect
import user_management as dbHandler
from urllib.parse import urlparse, urljoin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import os
import pyotp  # For generating and verifying TOTP
import qrcode  # For generating QR codes
from io import BytesIO
import base64


app = Flask(__name__)
app.secret_key = os.urandom(32)  # impossible to hack the secret_key 

# Whitelist of allowed URLs (relative paths)
ALLOWED_URLS = ["/", "/index.html", "/signup.html", "/success.html", "/logout"]

limiter = Limiter(
    get_remote_address,  # Use the client's IP address for rate-limiting
    app=app,
    default_limits=["1000 per day", "200 per hour"],  # Default limits for all routes
)

def is_safe_redirect_url(target):
    # Ensure the target URL is relative and in the whitelist
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.path in ALLOWED_URLS and ref_url.netloc == test_url.netloc

# Enable CSRF protection
csrf = CSRFProtect(app)

@app.route("/2fa-setup", methods=["GET", "POST"])
def setup_2fa():
    if request.method == "GET":
        # Generate a unique secret key for the user
        secret = pyotp.random_base32()
        session["2fa_secret"] = secret  # Temporarily store the secret in the session

        # Generate a QR code for the secret
        totp = pyotp.TOTP(secret)
        qr_url = totp.provisioning_uri(session["username"], issuer_name="SecurePWA")
        qr = qrcode.make(qr_url)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        buffer.seek(0)
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()

        return render_template("2fa_setup.html", qr_code=qr_base64)

    if request.method == "POST":
        # Verify the 6-digit TOTP entered by the user
        totp = pyotp.TOTP(session["2fa_secret"])
        otp = request.form["otp"]
        if totp.verify(otp):
            # Save the 2FA secret in the database
            dbHandler.save_2fa_secret(session["username"], session["2fa_secret"])
            session["2fa_verified"] = True  # Mark 2FA as completed
            return redirect(url_for("home"))
        else:
            error_message = "Invalid 2FA code. Please try again."
            return render_template("2fa_setup.html", error=error_message)
        

@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
@limiter.limit("50 per minute")  # Limit to 50 login attempts per minute
def home():
    if request.method == "GET":
        # Check if the user is already logged in
        if "username" in session and session.get("2fa_verified"):
            feedback_list = dbHandler.listFeedback()
            return render_template("/success.html", value=session["username"], state=True, feedback_list=feedback_list)
        elif "username" in session and not session.get("2fa_verified"):
            # Redirect to 2FA verification if not completed
            return redirect(url_for("verify_2fa"))
        return render_template("/index.html")

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]

        # Check login credentials
        isLoggedIn = dbHandler.retrieveUsers(username, password, email)
        if isLoggedIn:
            # Check if 2FA is enabled for the user
            secret = dbHandler.get_2fa_secret(username)
            if secret:
                # Store user information and 2FA secret in the session
                session["username"] = username
                session["2fa_secret"] = secret
                session["2fa_verified"] = False  # Ensure 2FA is not marked as completed
                return redirect(url_for("verify_2fa"))
            else:
                # Log in the user if 2FA is not enabled
                session["username"] = username
                session["email"] = email
                session["2fa_verified"] = True  # Mark as verified since 2FA is not enabled
                feedback_list = dbHandler.listFeedback()
                return render_template("/success.html", value=session["username"], state=True, feedback_list=feedback_list)
        else:
            # Generic error message for invalid login
            error_message = "Invalid username, password, or email. Please try again."
            return render_template("/index.html", error=error_message)
        
@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "GET":
        return render_template("/signup.html")
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        dob = request.form["dob"]
        email = request.form["email"]

        # Check if the username or email already exists
        if dbHandler.isUserExists(username, email):
            error_message = "Username or email already exists. Please try a different one."
            return render_template("/signup.html", error=error_message, username=username, email=email, dob=dob)

        # Validate username length
        if len(username) <= 6:
            error_message = "Invalid username. Username must be more than 6 characters."
            return render_template("/signup.html", error=error_message, username=username, email=email, dob=dob)

        # Validate password
        if not is_valid_password(password):
            error_message = "Invalid password. Password must be 12-32 characters long, contain at least 1 uppercase letter, 1 lowercase letter, and more than 4 numbers."
            return render_template("/signup.html", error=error_message, username=username, email=email, dob=dob)

        # Insert the user into the database
        dbHandler.insertUser(username, password, dob, email)

        # Store username in session for 2FA setup
        session["username"] = username
        return redirect(url_for("setup_2fa"))
        
@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if "username" not in session or not session.get("2fa_verified"):
        return redirect("/")  # Redirect to login if not logged in or 2FA not completed

    if request.method == "POST":
        feedback = request.form["feedback"]
        # Validate feedback
        if len(feedback) > 500:
            return "Invalid feedback", 400
        dbHandler.insertFeedback(feedback, session["username"])

    feedback_list = dbHandler.listFeedback()  # Get the feedback data
    return render_template("/success.html", state=True, value=session["username"], feedback_list=feedback_list)

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if request.method == "GET":
        # Ensure the user is logged in and has a 2FA secret
        if "username" not in session or "2fa_secret" not in session:
            return redirect("/")  # Redirect to login if not logged in or no 2FA secret
        return render_template("verify_2fa.html")

    if request.method == "POST":
        otp = request.form["otp"]
        totp = pyotp.TOTP(session["2fa_secret"])
        if totp.verify(otp):
            # Mark 2FA as completed
            session["2fa_verified"] = True
            return redirect("/success.html")
        else:
            error_message = "Invalid 2FA code. Please try again."
            return render_template("verify_2fa.html", error=error_message)
                
@app.route("/logout")
def logout():
    session.clear()  # Clear the session

    # Validate the next URL (if provided)
    next_url = request.args.get("next", "/")
    if not is_safe_redirect_url(next_url):
        next_url = "/"  # Default to a safe URL

    return redirect(next_url)
    
def is_valid_password(password):
    # Regex explanation:
    # ^(?=.*[a-z])       -> At least one lowercase letter
    # (?=.*[A-Z])        -> At least one uppercase letter
    # (?=.*\d.*\d.*\d.*\d) -> At least 4 numbers
    # [A-Za-z\d]{12,32}$ -> Length between 12 and 32 characters, only letters and numbers
    regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d.*\d.*\d.*\d)[A-Za-z\d]{12,32}$"
    return re.match(regex, password) is not None

@app.after_request
def add_header(response):
    # Disable caching
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response

@app.errorhandler(429)
def ratelimit_error(e):
    return "Too many login attempts. Please try again later.", 429

if __name__ == "__main__":
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
