from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, send_file  #新增 send_file
import pyotp
import bcrypt
import qrcode
import base64
import io
import os
import psycopg2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from psycopg2.extras import RealDictCursor
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import requests

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
                    otp_secret TEXT,
                    public_key TEXT   
                );
            ''')
            conn.commit()

# 初始化 USERDATADB 資料表
def init_userdata_db():
    with get_userdata_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    username TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    content BYTEA,
                    encrypted_private BYTEA,
                    nonce BYTEA,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (username, filename)
                );
            ''')
            conn.commit()


@app.route("/")
def index():
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "無效的 JSON 輸入"})

        username = data.get("username")
        password = data.get("password")
        public_key = data.get("publicKey")  # 前端傳的公鑰

        if not username or not password or not public_key:
            return jsonify({"success": False, "error": "缺少必要欄位"})

        # 你的註冊邏輯，例如密碼雜湊、存資料庫
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        otp_secret = pyotp.random_base32()

        try:
            with get_user_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT username FROM users WHERE username = %s;", (username,))
                    if cur.fetchone():
                        return jsonify({"success": False, "error": "該帳號名稱不可用"})

                    cur.execute(
                        "INSERT INTO users (username, password, otp_secret, public_key) VALUES (%s, %s, %s, %s);",
                        (username, pw_hash, otp_secret, public_key)
                    )
                    conn.commit()
        except Exception as e:
            return jsonify({"success": False, "error": "資料庫錯誤：" + str(e)})

        # 註冊成功後，嘗試產生 KMS key pair（若不存在）
        requests.post("http://localhost:6000/kms_register", json=data)

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
    enc_file_content = base64.b64decode(data['enc_file_content'])
    enc_data_key = base64.b64decode(data['enc_data_key'])
    nonce = base64.b64decode(data['nonce'])

    username = session.get("username")
    if not username:
        return jsonify({"status": "error", "message": "未登入"}), 401

    try:
        with get_userdata_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT username,filename FROM files WHERE username = %s AND filename = %s;", (username,filename))
                if cur.fetchone():
                    return jsonify({"success": False, "error": "檔名重複"})
                cur.execute(
                    "INSERT INTO files (username, filename, content, encrypted_private, nonce) VALUES (%s, %s, %s, %s, %s);",
                    (username, filename, enc_file_content, enc_data_key, nonce)
                )
                conn.commit()

        return jsonify({"status": "success","success": True})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/get_kms_key', methods=['POST'])
def get_kms_key():
    username = session.get("username")

    if not username:
        return jsonify({"success": False, "error": "用戶未登入"})
    
    try:
        with get_user_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT public_key FROM users WHERE username = %s;", (username,))
                result = cur.fetchone()
                if not result:
                    return jsonify({"success": False, "error": "使用者不存在"})
                user_pub_key = result["public_key"]  # base64 格式的公鑰字串

        # 將 public_key 加入 data dict 中
        data = request.get_json()
        data["username"] = username            # 可選：提供 username 給 KMS 做紀錄
        data["user_public_key"] = user_pub_key

        # 發送請求到 KMS 的簽章驗證路由
        verify_response = requests.post(
            "http://localhost:6000/kms_verify_signature",
            json=data,
            cookies=request.cookies
        )

        if not verify_response.ok:
            return jsonify(verify_response.json())

        # 驗證成功後，再取得 KMS 公鑰
        kms_response = requests.post(
            "http://localhost:6000/kms_public_key",
            json=data,
            cookies=request.cookies
        )

        if not kms_response.ok:
            return jsonify({"success": False, "error": "無法取得 KMS 公鑰"})

        # 回傳驗證結果與 KMS 公鑰
        return jsonify({
            "success": True,
            "message": "簽章驗證成功",
            "kms_public_key": kms_response.json().get("public_key")
        })

    except InvalidSignature:
        print("❌ 簽章驗證失敗")
        return jsonify({"success": False, "error": "簽章驗證失敗"})

    except Exception as e:
        return jsonify({"success": False, "error": f"系統錯誤：{str(e)}"})


@app.route("/download/<filename>", methods=["POST"])
def download_file(filename):
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    username = session["username"]
    if not username:
        return jsonify({"success": False, "error": "未登入使用者"}), 401
    try:
        with get_user_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT public_key FROM users WHERE username = %s;", (username,))
                result = cur.fetchone()
                user_pub_key = result["public_key"]  # base64 格式的公鑰字串

        data = request.get_json()
        data["username"] = username
        data["user_public_key"] = user_pub_key

        # 發送請求到 KMS 的簽章驗證路由
        verify_response = requests.post(
            "http://localhost:6000/kms_verify_signature",
            json=data,
            cookies=request.cookies
        )
        if not verify_response.ok:
            return jsonify(verify_response.json())
        
        with get_userdata_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT content, encrypted_private, nonce FROM files WHERE username = %s AND filename = %s;",
                    (username, filename)
                )
                file_data = cur.fetchone()

        data["encrypted_private"] = base64.b64encode(file_data["encrypted_private"].tobytes()).decode()

        kms_response = requests.post(
            "http://localhost:6000/kms_wrapped_AES",
            json=data,
            cookies=request.cookies,
        )

        return jsonify({
            "success": True,
            "content": base64.b64encode(file_data["content"].tobytes()).decode(),
            "encrypted_private": kms_response.json().get("wrapped_key"),
            "nonce": base64.b64encode(file_data["nonce"].tobytes()).decode()
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


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
    init_user_db()
    init_userdata_db()
    app.run(debug=True)
