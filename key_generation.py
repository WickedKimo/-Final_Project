from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# 確保 static 資料夾存在
os.makedirs('static', exist_ok=True)

# 生成 RSA 密鑰對
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# 生成公鑰
public_key = private_key.public_key()

# 將公鑰轉換為 PEM 格式
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 將公鑰寫入 static/public_key.txt
with open('static/public_key.txt', 'wb') as f:
    f.write(pem)

print("✅ 公鑰已寫入 static/public_key.txt！")