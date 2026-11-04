"""Emisión y validación de JWT (acceso y renovación). Sin dependencias de la web."""
import uuid
from datetime import datetime, timedelta, timezone

import jwt

ALGORITMO = "HS256"
OBLIGATORIOS = ["exp", "iat", "sub", "sid", "jti", "typ"]


class TokenError(Exception):
    """Token ausente, vencido, manipulado o de tipo incorrecto."""


def emitir(secret: str, tipo: str, sub, sid: str, rol: str, vigencia: timedelta,
           jti: str | None = None, ahora: datetime | None = None):
    """Devuelve (token, jti, vencimiento)."""
    ahora = ahora or datetime.now(timezone.utc)
    jti = jti or uuid.uuid4().hex
    payload = {
        "sub": str(sub), "sid": sid, "rol": rol, "typ": tipo, "jti": jti,
        "iat": ahora, "exp": ahora + vigencia,
    }
    return jwt.encode(payload, secret, algorithm=ALGORITMO), jti, payload["exp"]


def validar(secret: str, token: str, tipo: str) -> dict:
    try:
        datos = jwt.decode(token, secret, algorithms=[ALGORITMO],
                           options={"require": OBLIGATORIOS})
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    if datos.get("typ") != tipo:
        raise TokenError("Tipo de token incorrecto")
    return datos
