from flask import Flask
import base64
import os
import psycopg2
from flask import Blueprint, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv

load_dotenv()

# 載入 KMSDB 連線字串
KMSDB_URL = os.environ.get("KMSDB_URL")


kms = Flask(__name__)


def get_kms_db_connection():
    return psycopg2.connect(KMSDB_URL)


# 建立 Blueprint
kms_bp = Blueprint('kms', __name__, url_prefix='/kms')


# 初始化 KMSDB 資料庫
def init_kms_db():
    with get_kms_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS kms_keys (
                    username TEXT PRIMARY KEY,
                    private_key BYTEA NOT NULL,
                    public_key BYTEA NOT NULL
                );
            ''')
            conn.commit()


@kms.route('/kms_register', methods=['POST'])
def generate_and_store_kms_keypair():
    data = request.get_json()
    username = data.get("username")
    with get_kms_db_connection() as conn:
        with conn.cursor() as cur:
            # 生成金鑰對
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()

            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # 插入資料庫
            cur.execute(
                "INSERT INTO kms_keys (username, private_key, public_key) VALUES (%s, %s, %s);",
                (username, private_bytes, public_bytes)
            )
            conn.commit()
            return jsonify({"success": True})
    

@kms.route('/kms_public_key', methods=['POST'])
def get_kms_public_key():
    data = request.get_json()
    username = data.get("username")
    try:
        with get_kms_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT public_key FROM kms_keys WHERE username = %s;", (username,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"success": False, "error": "KMS 公鑰不存在"})
                pem_str = bytes(row[0]).decode()  # decode 成 UTF-8 字串
        return jsonify({"success": True, "public_key": pem_str})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@kms.route('/kms_verify_signature', methods=['POST'])
def route_verify_signature():
    data = request.get_json()

    signature_data = data.get("signature")
    message = data.get("message")
    public_key_b64 = data.get("user_public_key")  # 從 request 拿 public key

    if not signature_data or not message or not public_key_b64:
        return jsonify({"success": False, "error": "缺少必要資料"})

    # decode 公鑰
    try:
        signature = (
            base64.b64decode(signature_data)
            if isinstance(signature_data, str)
            else bytes(signature_data)
        )
        message_bytes = message.encode()

        user_public_key = serialization.load_der_public_key(
            base64.b64decode(public_key_b64)
        )

        # 驗證簽章
        user_public_key.verify(
            signature,
            message_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    except InvalidSignature:
        return jsonify({"success": False, "error": "簽章驗證失敗"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"發生錯誤: {str(e)}"}), 500

    return jsonify({"success": True, "message": "簽章驗證成功"})


@kms.route('/kms_wrapped_AES', methods=['POST'])
def get_wrapped_AES():

    data = request.get_json()
    username = data.get("username")
    encrypted_private_b64 = data.get("encrypted_private")
    user_public_key_b64 = data.get("user_public_key")

    try:
        with get_kms_db_connection() as conn:
            with conn.cursor() as cur:

                # 1. 取出 KMS 私鑰（PEM 格式）
                cur.execute("SELECT private_key FROM kms_keys WHERE username = %s;", (username,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"success": False, "error": "KMS 私鑰不存在"})
                pem_str = bytes(row[0])  # still in bytes
 
                # 2. 載入 KMS 私鑰
                kms_private_key = serialization.load_pem_private_key(
                    pem_str,
                    password=None
                )

                print(f"kms_private_key={kms_private_key}")

                # 3. 解 base64 成原始加密內容（bytes）
                encrypted_private = base64.b64decode(encrypted_private_b64)

                print(f"encrypted_private={encrypted_private}")

                # 4. 用 KMS 私鑰解密
                decrypted = kms_private_key.decrypt(
                    encrypted_private,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                print(f"decrypted={decrypted}")

                # 5. 載入使用者的 public key（PEM 格式）
                user_public_pem = base64.b64decode(user_public_key_b64)
                user_public_key = serialization.load_pem_public_key(user_public_pem)

                # 6. 用使用者的 public key 加密解密後的結果
                re_encrypted = user_public_key.encrypt(
                    decrypted,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                print(f"re_encrypted={re_encrypted}")

                # 7. base64 回傳
                return jsonify({
                    "success": True,
                    "wrapped_key": base64.b64encode(re_encrypted).decode()
                })
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == "__main__":
    init_kms_db()
    kms.run(port=6000)
