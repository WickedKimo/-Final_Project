# kms.py
from flask import Blueprint

kms_bp = Blueprint("kms", __name__)

@kms_bp.route("/kms/ping")
def ping():
    return "KMS module is alive!"