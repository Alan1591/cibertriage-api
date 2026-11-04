"""Bitácora encadenada: cada registro incluye el hash del anterior (detecta alteraciones)."""
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Auditoria, ahora

GENESIS = "0" * 64


def _f(fecha) -> str:
    """Formato fijo (SQLite devuelve fechas sin zona; PostgreSQL con zona)."""
    return fecha.strftime("%Y-%m-%dT%H:%M:%S")


def calcular(previo: str, fecha_iso: str, actor: str, accion: str, detalle: str, ip: str) -> str:
    base = "|".join([previo, fecha_iso, actor, accion, detalle, ip])
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def registrar(db: Session, actor: str, accion: str, detalle: str = "", ip: str = "") -> Auditoria:
    ultimo = db.scalars(select(Auditoria).order_by(Auditoria.id.desc()).limit(1)).first()
    previo = ultimo.hash if ultimo else GENESIS
    reg = Auditoria(actor=actor, accion=accion, detalle=detalle, ip=ip, hash_previo=previo, hash="")
    reg.fecha = ahora().replace(microsecond=0)
    reg.hash = calcular(previo, _f(reg.fecha), actor, accion, detalle, ip)
    db.add(reg)
    db.flush()
    return reg


def verificar_cadena(db: Session) -> dict:
    previo = GENESIS
    total = 0
    for reg in db.scalars(select(Auditoria).order_by(Auditoria.id)):
        total += 1
        esperado = calcular(previo, _f(reg.fecha), reg.actor, reg.accion, reg.detalle, reg.ip)
        if reg.hash_previo != previo or reg.hash != esperado:
            return {"integra": False, "registros": total, "primer_error_id": reg.id}
        previo = reg.hash
    return {"integra": True, "registros": total, "primer_error_id": None}
