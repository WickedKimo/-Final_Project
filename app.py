from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
import pyotp
import bcrypt
import qrcode
import base64
import io
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
load_dotenv()


# 連線到 PostgreSQL（Render 提供 USERDB_URL 和 USERDATADB_URL）
USERDB_URL = os.environ.get("USERDB_URL")
USERDATADB_URL = os.environ.get("USERDATADB_URL")

app = Flask(__name__)
app.secret_key = "secret"

# 用於 USERDB 的資料庫連線
def get_user_db_connection():
    return psycopg2.connect(USERDB_URL, cursor_factory=RealDictCursor)

# 用於 USERDATADB 的資料庫連線
def get_userdata_db_connection():
    return psycopg2.connect(USERDATADB_URL, cursor_factory=RealDictCursor)

# 初始化 USERDB 資料表
def init_user_db():
    with get_user_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password BYTEA,
                    otp_secret TEXT
                );
            ''')
            conn.commit()

# 初始化 USERDATADB 資料表
def init_userdata_db():
    with get_userdata_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    username TEXT PRIMARY KEY,
                    filename TEXT,
                    content BYTEA,
                    encrypted_private BYTEA,
                    nonce BYTEA,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            conn.commit()


@app.route("/")
def index():
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # 這是前端 AJAX 提交的 POST 請求
        username = request.form["username"]
        password = request.form["password"]

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        otp_secret = pyotp.random_base32()

        try:
            with get_user_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT username FROM users WHERE username = %s;", (username,))
                    if cur.fetchone():
                        return jsonify({"success": False, "error": "該帳號名稱不可用"})

                    cur.execute("INSERT INTO users (username, password, otp_secret) VALUES (%s, %s, %s);",
                                (username, pw_hash, otp_secret))
                    conn.commit()
        except Exception as e:
            return jsonify({"success": False, "error": "資料庫錯誤：" + str(e)})

        # 成功，產生 QR Code 並轉為 base64
        uri = pyotp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name="MyCloud")
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        return jsonify({"success": True, "qr_b64": qr_b64})

    # GET 請求時直接回傳 HTML 表單頁面
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        try:
            with get_user_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT password FROM users WHERE username = %s;", (username,))
                    user = cur.fetchone()

            if not user or not bcrypt.checkpw(password.encode(), user["password"].tobytes()):
                return jsonify(success=False, error="帳號密碼錯誤或帳號尚未啟用")

            session["username"] = username
            return jsonify(success=True)

        except Exception as e:
            return jsonify(success=False, error="伺服器錯誤，請稍後再試")

    # method == "GET" 時，回傳登入 HTML 頁面
    return render_template("login.html")


@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    print("Session received username:", session.get("username"))
    username = session.get("username")
    if not username:
        return jsonify(success=False, error="尚未登入")

    otp_input = request.form.get("otp")

    try:
        with get_user_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT otp_secret FROM users WHERE username = %s;", (username,))
                user = cur.fetchone()

        if not user:
            return jsonify(success=False, error="帳號不存在")

        totp = pyotp.TOTP(user["otp_secret"])
        if totp.verify(otp_input):
            session["authenticated"] = True  # ✅ 登入驗證完成，設為 True
            return jsonify(success=True)  # 登入驗證成功！
        else:
            return jsonify(success=False, error="驗證碼錯誤")

    except Exception as e:
        return jsonify(success=False, error="伺服器錯誤")


@app.route("/WebCrypto_API")
def WebCrypto_API():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    # 列出該使用者的檔案
    try:
        with get_userdata_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT filename FROM files WHERE username = %s;", (session["username"],))
                files = cur.fetchall()
    except Exception as e:
        flash("資料庫錯誤：" + str(e))
        files = []

    return render_template("WebCrypto_API.html", files=files, username=session["username"])


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/upload", methods=["POST"])
def upload():
    data = request.get_json()

    filename = data.get("filename")
    enc_file_content = data.get("enc_file_content")
    enc_data_key = data.get("enc_data_key")
    nonce = data.get("nonce")

    username = session.get("username")
    if not username:
        return jsonify({"status": "error", "message": "未登入"}), 401

    # 轉換成 bytes
    enc_file_content_bytes = bytes(enc_file_content)
    enc_data_key_bytes = bytes(enc_data_key)
    nonce_bytes = bytes(nonce)

    try:
        with get_userdata_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO files (username, filename, content, encrypted_private, nonce) VALUES (%s, %s, %s, %s, %s);",
                    (username, filename, enc_file_content_bytes, enc_data_key_bytes, nonce_bytes)
                )
                conn.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
'''
@app.route("/upload", methods=["POST"])
def upload():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    file = request.files["file"]
    if file:
        filename = secure_filename(file.filename)
        file_data = file.read()

        # 在這裡進行加密處理（假設加密是另一個服務或函式進行的）
        # 加密後的檔案會傳回給 Flask 應用，並儲存到資料庫中
        encrypted_data = file_data  # 假設加密過的檔案資料已經處理好了

        try:
            with get_userdata_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("INSERT INTO files (username, filename, content) VALUES (%s, %s, %s);",
                                (session["username"], filename, encrypted_data))
                    conn.commit()
            flash("檔案上傳成功")
        except Exception as e:
            flash("檔案上傳失敗：" + str(e))

    return redirect(url_for("WebCrypto_API"))
'''
@app.route("/download/<int:file_id>", methods=["GET"])
def download(file_id):
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    try:
        with get_userdata_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT filename, content FROM files WHERE id = %s;", (file_id,))
                file = cur.fetchone()

        if file:
            # 下載的檔案直接返回，這裡假設檔案已經是加密過的
            return send_file(io.BytesIO(file["content"]), download_name=file["filename"], as_attachment=True)
        else:
            flash("檔案不存在")
            return redirect(url_for("WebCrypto_API"))
    except Exception as e:
        flash("下載失敗：" + str(e))
        return redirect(url_for("WebCrypto_API"))

@app.route("/delete", methods=["POST"])
def delete():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    filename = request.form["delete_filename"]
    try:
        with get_userdata_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM files WHERE username = %s AND filename = %s;", (session["username"], filename))
                conn.commit()
        flash("檔案刪除成功")
    except Exception as e:
        flash("刪除失敗：" + str(e))

    return redirect(url_for("WebCrypto_API"))

if __name__ == "__main__":
    init_user_db()  # 初始化 USERDB 資料庫
    init_userdata_db()  # 初始化 USERDATADB 資料庫
    app.run(debug=True)
