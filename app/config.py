"""Configuración de CiberTriage. Todo secreto se lee de variables de entorno."""
import base64
import os
import secrets
from dataclasses import dataclass


def _b64_key(valor: str) -> bytes:
    clave = base64.urlsafe_b64decode(valor.encode() + b"=" * (-len(valor) % 4))
    if len(clave) != 32:
        raise ValueError("ENCRYPTION_KEY debe decodificar a 32 bytes (AES-256).")
    return clave


def _database_url() -> str:
    url = os.getenv("DATABASE_URL", "sqlite:///./cibertriage.db")
    # Render entrega 'postgres://', SQLAlchemy necesita 'postgresql://'
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return url


@dataclass(frozen=True)
class Settings:
    database_url: str
    secret_key: str
    encryption_key: bytes
    access_minutes: int = 15
    session_hours: int = 8
    idle_minutes: int = 15
    max_login_failures: int = 5
    lockout_minutes: int = 15
    max_file_bytes: int = 10 * 1024 * 1024
    max_files: int = 10
    trust_proxy: bool = False
    admin_user: str = ""
    admin_password: str = ""
    admin_name: str = "Administrador"


def load_settings() -> Settings:
    entorno_prod = os.getenv("APP_ENV", "dev") == "prod"
    secret = os.getenv("SECRET_KEY", "")
    enc = os.getenv("ENCRYPTION_KEY", "")
    if entorno_prod and (len(secret) < 32 or not enc):
        raise RuntimeError(
            "En producción deben definirse SECRET_KEY (>= 32 caracteres) y ENCRYPTION_KEY."
        )
    if not secret:  # solo desarrollo: clave efímera (invalida sesiones al reiniciar)
        secret = secrets.token_urlsafe(48)
    key = _b64_key(enc) if enc else secrets.token_bytes(32)
    return Settings(
        database_url=_database_url(),
        secret_key=secret,
        encryption_key=key,
        trust_proxy=os.getenv("TRUST_PROXY", "0") == "1",
        admin_user=os.getenv("ADMIN_USER", ""),
        admin_password=os.getenv("ADMIN_PASSWORD", ""),
        admin_name=os.getenv("ADMIN_NAME", "Administrador"),
    )
