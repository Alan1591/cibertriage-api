from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# Esquemas para Alertas Públicas
class AlertaBase(BaseModel):
    tipo_dato: str
    valor: str
    modalidad: str
    provincia: Optional[str] = "Entre Ríos"
    localidad: str
    comentario: Optional[str] = None

class AlertaCreate(AlertaBase):
    pass

class AlertaOut(AlertaBase):
    id: int
    fecha_creacion: Optional[datetime] = None

    class Config:
        from_attributes = True

# Esquemas para Denuncias Policiales
class DenunciaBase(BaseModel):
    comisaria: Optional[str] = None
    localidad: str
    provincia: Optional[str] = "Entre Ríos"
    modalidad: str
    cbu: Optional[str] = None
    alias: Optional[str] = None
    telefono: Optional[str] = None
    url_phishing: Optional[str] = None
    red_social: Optional[str] = None
    monto: Optional[float] = 0.0
    latitud: Optional[float] = None
    longitud: Optional[float] = None

class DenunciaCreate(DenunciaBase):
    hash_manual: Optional[str] = None

class DenunciaOut(DenunciaBase):
    id: int
    hash_evidencia: Optional[str] = None
    archivo_ruta: Optional[str] = None
    elevado_judicial: Optional[bool] = False
    fecha_creacion: Optional[datetime] = None

    class Config:
        from_attributes = True