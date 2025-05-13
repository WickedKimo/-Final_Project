from flask import Flask, render_template, request, redirect, session, url_for, flash
import pyotp
import bcrypt
import qrcode
import base64
import io
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import cloudinary.api
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
<<<<<<< HEAD
load_dotenv()  
=======
load_dotenv()
>>>>>>> 77d2cd986c7ffffc754161efbfd004e2e01941a0

cloudinary.config(
    cloud_name=os.environ['CLOUDINARY_CLOUD_NAME'],
    api_key=os.environ['CLOUDINARY_API_KEY'],
    api_secret=os.environ['CLOUDINARY_API_SECRET']
)

# 連線到 PostgreSQL（Render 提供 DATABASE_URL）
DATABASE_URL = os.environ.get("DATABASE_URL")

app = Flask(__name__)
app.secret_key = "secret"

def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

# 初始化 users 資料表
def init_db():
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password BYTEA,
                    otp_secret TEXT
                );
            ''')
            conn.commit()

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        otp_secret = pyotp.random_base32()

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT username FROM users WHERE username = %s;", (username,))
                    if cur.fetchone():
                        flash("此帳號已註冊")
                        return redirect(url_for("register"))

                    cur.execute("INSERT INTO users (username, password, otp_secret) VALUES (%s, %s, %s);",
                                (username, pw_hash, otp_secret))
                    conn.commit()
        except Exception as e:
            flash("資料庫錯誤：" + str(e))
            return redirect(url_for("register"))

        # 產生 QR Code
        uri = pyotp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name="MyCloud")
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        return render_template("show_qr.html", qr_b64=qr_b64, otp_secret=otp_secret)

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT password, otp_secret FROM users WHERE username = %s;", (username,))
                    user = cur.fetchone()

            if not user or not bcrypt.checkpw(password.encode(), user["password"].tobytes()):
                flash("帳密錯誤")
                return redirect(url_for("login"))

            session["username"] = username
            return redirect(url_for("verify_otp"))

        except Exception as e:
            flash("登入錯誤：" + str(e))
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT otp_secret FROM users WHERE username = %s;", (username,))
                row = cur.fetchone()
                if not row:
                    flash("找不到使用者")
                    return redirect(url_for("login"))
                otp_secret = row["otp_secret"]
    except Exception as e:
        flash("資料庫錯誤：" + str(e))
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_code = request.form["otp"]
        totp = pyotp.TOTP(otp_secret)

        if totp.verify(otp_code):
            session["authenticated"] = True
            return redirect(url_for("WebCrypto_API"))
        else:
            flash("OTP 錯誤")
            return redirect(url_for("verify_otp"))

    return render_template("otp_verification.html")

@app.route("/WebCrypto_API")
def WebCrypto_API():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    # 列出該使用者的檔案
    try:
        result = cloudinary.api.resources(type="upload", prefix=f"{session['username']}/")
        files = [res["public_id"].split("/", 1)[-1] for res in result.get("resources", [])]
    except Exception:
        files = []

    return render_template("WebCrypto_API.html", files=files)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/upload", methods=["POST"])
def upload():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    file = request.files["file"]
    if file:
        filename = secure_filename(file.filename)
        result = cloudinary.uploader.upload(file, public_id=f"{session['username']}/{filename}")
        flash("檔案上傳成功")
    return redirect(url_for("WebCrypto_API"))

@app.route("/download", methods=["POST"])
def download():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    filename = request.form["filename"]
    public_id = f"{session['username']}/{filename}"
    try:
        # 取得下載連結
        result = cloudinary.CloudinaryImage(public_id).build_url()
        return redirect(result)
    except Exception:
        flash("檔案不存在")
        return redirect(url_for("WebCrypto_API"))

@app.route("/delete", methods=["POST"])
def delete():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    filename = request.form["delete_filename"]
    public_id = f"{session['username']}/{filename}"
    try:
        cloudinary.uploader.destroy(public_id)
        flash("檔案已刪除")
    except Exception:
        flash("刪除失敗")
    return redirect(url_for("WebCrypto_API"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)