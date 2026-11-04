"""Funciones criptográficas puras (sin dependencias de la web ni de la base)."""
import hashlib
import hmac
import os
import re
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TIPOS_IOC = ("CBU_CVU", "ALIAS", "TELEFONO", "URL")
NONCE_BYTES = 12


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_stream(f: BinaryIO, bloque: int = 65536) -> str:
    h = hashlib.sha256()
    for parte in iter(lambda: f.read(bloque), b""):
        h.update(parte)
    return h.hexdigest()


def cifrar(clave: bytes, datos: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM. Devuelve nonce || texto cifrado || etiqueta."""
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(clave).encrypt(nonce, datos, aad)


def descifrar(clave: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Lanza ValueError si el contenido fue alterado o la clave no corresponde."""
    try:
        return AESGCM(clave).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad)
    except InvalidTag as exc:
        raise ValueError("Contenido alterado o clave incorrecta") from exc


def normalizar_ioc(tipo: str, valor: str) -> str:
    if tipo not in TIPOS_IOC:
        raise ValueError("Tipo de IoC no soportado")
    v = (valor or "").strip()
    if tipo == "CBU_CVU":
        v = re.sub(r"\D", "", v)
        if len(v) != 22:
            raise ValueError("El CBU/CVU debe tener 22 dígitos")
    elif tipo == "ALIAS":
        v = v.lower().replace(" ", "")
        if not re.fullmatch(r"[a-z0-9.\-_]{6,20}", v):
            raise ValueError("Alias inválido (6 a 20 caracteres: letras, números, . - _)")
    elif tipo == "TELEFONO":
        v = re.sub(r"\D", "", v)
        for prefijo in ("549", "54"):
            if v.startswith(prefijo) and len(v) > 10:
                v = v[len(prefijo):]
                break
        v = v.lstrip("0")
        if not 8 <= len(v) <= 12:
            raise ValueError("Número de teléfono inválido")
    else:  # URL
        v = v.lower()
        v = re.sub(r"^[a-z]+://", "", v)
        v = re.sub(r"^www\.", "", v).rstrip("/")
        if "." not in v or len(v) < 4 or " " in v:
            raise ValueError("URL inválida")
    return v


def hash_ioc(pimienta: str, tipo: str, valor_normalizado: str) -> str:
    """HMAC-SHA256 con clave secreta (impide reconstruir valores por diccionario)."""
    mensaje = f"{tipo}|{valor_normalizado}".encode("utf-8")
    return hmac.new(pimienta.encode("utf-8"), mensaje, hashlib.sha256).hexdigest()


# Tipos de archivo admitidos, verificados por contenido (no por extensión)
_FIRMAS = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


def detectar_tipo(contenido: bytes) -> str | None:
    for firma, mime in _FIRMAS:
        if contenido.startswith(firma):
            return mime
    if contenido[:4] == b"RIFF" and contenido[8:12] == b"WEBP":
        return "image/webp"
    return None


def comparar_seguro(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

