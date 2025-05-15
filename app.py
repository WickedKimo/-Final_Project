from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, send_file  #新增 send_file
import pyotp
import bcrypt
import qrcode
import base64
import io
import os
import psycopg2
from cryptography.hazmat.primitives import hashes, serialization   #新增的
from cryptography.hazmat.primitives.asymmetric import padding   #新增的
from cryptography.exceptions import InvalidSignature #新增的
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
                cur.execute("SELECT username,filename FROM files WHERE username = %s AND filename = %s;", (username,filename))
                if cur.fetchone():
                    return jsonify({"success": False, "error": "檔名重複"})
                cur.execute(
                    "INSERT INTO files (username, filename, content, encrypted_private, nonce) VALUES (%s, %s, %s, %s, %s);",
                    (username, filename, enc_file_content_bytes, enc_data_key_bytes, nonce_bytes)
                )
                conn.commit()
        return jsonify({"status": "success","success": True})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    
# 模擬：使用者對應的公鑰（實際可放資料庫）
USER_PUBLIC_KEY_PATH = "./static/user_public_keys/user1.pem"
KMS_PUBLIC_KEY_PATH = "./static/kms_public_key.pem"  # 你真正 KMS 要給的公鑰

@app.route('/get_kms_key', methods=['POST'])
def get_kms_key():
    data = request.get_json()
    username = session.get("username")
    if not username:
        return jsonify({"success": False, "error": "用戶未登入"})

    try:
        signature_data = data['signature']

        # 偵測型態
        if isinstance(signature_data, str):
            # base64字串
            signature = base64.b64decode(signature_data)
        elif isinstance(signature_data, list):
            # list of int
            signature = bytes(signature_data)
        else:
            return jsonify({"success": False, "error": "無效的簽章格式"})

        message = data['message'].encode()

        # 從資料庫取出用戶公鑰字串 (PEM格式)
        with get_user_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT public_key FROM users WHERE username = %s;", (username,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"success": False, "error": "用戶不存在"})

                public_key_base64 = row['public_key']

        public_key_der = base64.b64decode(public_key_base64)
        user_public_key = serialization.load_der_public_key(public_key_der)
        print("2")
        print("收到的 message: ", message)
        print("收到的 signature: ", signature)
        print("資料庫 user_public_key: ", user_public_key)
        # 驗證簽章
        user_public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("3")

        # 驗證成功，讀取 KMS 公鑰並回傳

        with open("./static/kms_public_key.pem", "rb") as f:
            kms_pub_pem = f.read()
        print("4")
        return jsonify({
            "success": True,
            "kms_public_key": kms_pub_pem.decode()  # 回傳文字格式 PEM 公鑰
        })

    except InvalidSignature:
        print("❌ 簽章驗證失敗")
        return jsonify({"success": False, "error": "簽章驗證失敗"})

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
