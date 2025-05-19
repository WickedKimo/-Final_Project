# kms.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

KMSDB_URL = os.environ.get("KMSDB_URL")

def get_kms_db_connection():
    return psycopg2.connect(KMSDB_URL)

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

def generate_and_store_keys(username):
    # 生成RSA密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # 序列化密钥
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 存储到数据库
    with get_kms_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO kms_keys (username, private_key, public_key) VALUES (%s, %s, %s);",
                (username, private_pem, public_pem)
            )
            conn.commit()

    return public_pem.decode()

def get_private_key(username, signature, message):
    with get_kms_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT private_key FROM kms_keys WHERE username = %s;", (username,))
            result = cur.fetchone()
            if not result:
                return None
            return result[0].tobytes()
