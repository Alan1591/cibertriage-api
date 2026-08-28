from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.sql import func
from database import Base

class AlertaPublica(Base):
    __tablename__ = "alertas_publicas"

    id = Column(Integer, primary_key=True, index=True)
    tipo_dato = Column(String, index=True)  # CBU, Alias, Telefono, URL
    valor = Column(String, index=True)
    modalidad = Column(String)
    provincia = Column(String, default="Entre Ríos")
    localidad = Column(String)
    comentario = Column(String, nullable=True)
    fecha_creacion = Column(DateTime(timezone=True), server_default=func.now())

class DenunciaPolicial(Base):
    __tablename__ = "denuncias_policiales"

    id = Column(Integer, primary_key=True, index=True)
    comisaria = Column(String)
    localidad = Column(String)
    provincia = Column(String, default="Entre Ríos")
    modalidad = Column(String)
    cbu = Column(String, nullable=True, index=True)
    alias = Column(String, nullable=True, index=True)
    telefono = Column(String, nullable=True, index=True)
    url_phishing = Column(String, nullable=True)
    red_social = Column(String, nullable=True)
    monto = Column(Float, default=0.0)
    hash_evidencia = Column(String, nullable=True)
    archivo_ruta = Column(String, nullable=True)
    latitud = Column(Float, nullable=True)
    longitud = Column(Float, nullable=True)
    elevado_judicial = Column(Boolean, default=False)
    fecha_creacion = Column(DateTime(timezone=True), server_default=func.now())