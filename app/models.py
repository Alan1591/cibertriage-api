from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def ahora() -> datetime:
    return datetime.now(timezone.utc)


class Usuario(Base):
    __tablename__ = "usuarios"
    id: Mapped[int] = mapped_column(primary_key=True)
    usuario: Mapped[str] = mapped_column(String(60), unique=True, index=True)
    nombre: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(100))
    rol: Mapped[str] = mapped_column(String(30))  # oficial_auditoria | administrador
    activo: Mapped[bool] = mapped_column(Boolean, default=True)
    intentos_fallidos: Mapped[int] = mapped_column(Integer, default=0)
    bloqueado_hasta: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Sesion(Base):
    __tablename__ = "sesiones"
    sid: Mapped[str] = mapped_column(String(40), primary_key=True)
    usuario_id: Mapped[int] = mapped_column(ForeignKey("usuarios.id"), index=True)
    refresh_jti: Mapped[str] = mapped_column(String(40))
    creada: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=ahora)
    ultima_actividad: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=ahora)
    expira: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revocada: Mapped[bool] = mapped_column(Boolean, default=False)
    usuario: Mapped[Usuario] = relationship()


class Reporte(Base):
    __tablename__ = "reportes"
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    fecha: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=ahora)
    tipologia: Mapped[str] = mapped_column(String(60), index=True)
    monto_ars: Mapped[int | None] = mapped_column(Integer, nullable=True)
    relato_cifrado: Mapped[bytes] = mapped_column(LargeBinary)
    denunciante_cifrado: Mapped[bytes] = mapped_column(LargeBinary)  # JSON con datos personales
    estado: Mapped[str] = mapped_column(String(20), default="pendiente")
    iocs: Mapped[list["IoC"]] = relationship(cascade="all, delete-orphan")
    evidencias: Mapped[list["Evidencia"]] = relationship(cascade="all, delete-orphan")


class IoC(Base):
    __tablename__ = "iocs"
    id: Mapped[int] = mapped_column(primary_key=True)
    reporte_id: Mapped[int] = mapped_column(ForeignKey("reportes.id"), index=True)
    tipo: Mapped[str] = mapped_column(String(20))
    hash_ioc: Mapped[str] = mapped_column(String(64), index=True)  # HMAC-SHA256, nunca el valor
    valor_cifrado: Mapped[bytes] = mapped_column(LargeBinary)  # visible solo para personal autorizado


class Evidencia(Base):
    __tablename__ = "evidencias"
    id: Mapped[int] = mapped_column(primary_key=True)
    reporte_id: Mapped[int] = mapped_column(ForeignKey("reportes.id"), index=True)
    nombre_original: Mapped[str] = mapped_column(String(200))
    mime: Mapped[str] = mapped_column(String(60))
    tamano: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))  # del archivo original, calculado al recibirlo
    contenido_cifrado: Mapped[bytes] = mapped_column(LargeBinary)
    recibida: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=ahora)


class Auditoria(Base):
    __tablename__ = "auditoria"
    id: Mapped[int] = mapped_column(primary_key=True)
    fecha: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=ahora)
    actor: Mapped[str] = mapped_column(String(60))
    accion: Mapped[str] = mapped_column(String(60))
    detalle: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    hash_previo: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
