import hashlib
import os
import json
import secrets
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from sqlalchemy.orm import Session
import models, schemas
from database import engine, get_db

# Crear tablas en PostgreSQL / SQLite
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="CiberTriage - Plataforma Policial de Reportes Digitales e IoCs",
    description="Sistema de preservación de evidencia digital (ISO/IEC 27037) y prevención comunitaria (Ley N° 25.326)",
    version="2.1.0"
)

# Configuración de archivos estáticos y vistas HTML
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------------------------------------------------------------
# FUNCIONES CRIPTOGRÁFICAS DE SEGURIDAD (ISO/IEC 27037)
# ---------------------------------------------------------------------

def calcular_sha256_stream(file_path: str) -> str:
    """Calcula la huella SHA-256 leyendo por bloques de 64 KB (Streaming) para asegurar la integridad de archivos grandes."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest().upper()

def anonimizar_ioc(valor: str) -> str:
    """Genera un hash normalizado del IoC para consulta anónima (Privacy by Design)."""
    normalizado = valor.strip().upper().replace(" ", "").replace("-", "")
    return hashlib.sha256(normalizado.encode('utf-8')).hexdigest()

# ---------------------------------------------------------------------
# VISTAS FRONTEND
# ---------------------------------------------------------------------

@app.get("/")
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# ---------------------------------------------------------------------
# ENDPOINTS API RESTFUL
# ---------------------------------------------------------------------

# 1. Cargar Reporte Digital con Carga Completa de Indicadores y Evidencia
@app.post("/api/reporte-digital", response_model=schemas.PreDenunciaResponse, status_code=status.HTTP_201_CREATED)
async def crear_reporte_digital(
    tipologia_delito: str = Form(...),
    descripcion_hecho: str = Form(...),
    monto_estimado_ars: float = Form(0.0),
    cuil_dni: str = Form(...),
    nombre_apellido: str = Form(...),
    email: str = Form(...),
    telefono_contacto: Optional[str] = Form(None),
    # Campos completos del sospechoso / involucrados (Diseño Original)
    cbu_cvu_sospechoso: Optional[str] = Form(None),
    alias_sospechoso: Optional[str] = Form(None),
    telefono_sospechoso: Optional[str] = Form(None),
    url_sitio_falso: Optional[str] = Form(None),
    archivos: List[UploadFile] = File(...),
    db: Session = Depends(get_db)
):
    # Registrar o recuperar usuario emisor del reporte
    user = db.query(models.User).filter(models.User.cuil_dni == cuil_dni).first()
    if not user:
        user = models.User(
            cuil_dni=cuil_dni,
            nombre_apellido=nombre_apellido,
            email=email,
            telefono=telefono_contacto,
            hash_password="NO_PASSWORD_REPORTE_DIGITAL",
            rol="ciudadano"
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    # Generar Identificador de Reporte Digital (Ej: RD-PER-8F91A2)
    ticket_codigo = f"RD-PER-{secrets.token_hex(3).upper()}"

    reporte = models.PreDenuncia(
        usuario_id=user.id,
        numero_ticket=ticket_codigo,
        tipologia_delito=tipologia_delito,
        descripcion_hecho=descripcion_hecho,
        monto_estimado_ars=monto_estimado_ars,
        estado_tramite="PENDIENTE_VERIFICACION" # Cambio de estado: PENDIENTE_VERIFICACION
    )
    db.add(reporte)
    db.commit()
    db.refresh(reporte)

    # Registrar Indicadores de Riesgo (IoCs) del Sospechoso recibidos en el diseño original
    iocs_a_registrar = [
        ("CBU_CVU", cbu_cvu_sospechoso),
        ("ALIAS", alias_sospechoso),
        ("TELEFONO", telefono_sospechoso),
        ("URL", url_sitio_falso)
    ]

    for tipo, valor in iocs_a_registrar:
        if valor and valor.strip():
            valor_limpio = valor.strip()
            nuevo_ioc = models.IoCReportado(
                predenuncia_id=reporte.id,
                tipo_ioc=tipo,
                valor_raw=valor_limpio,
                hash_ioc=anonimizar_ioc(valor_limpio),
                estado_ioc="PENDIENTE" # Se activa tras la verificación policial
            )
            db.add(nuevo_ioc)

    # Procesar Archivos y Fichar Hash SHA-256 Inalterable por Chunks
    for file in archivos:
        location = os.path.join(UPLOAD_DIR, f"{reporte.id}_{file.filename}")
        
        with open(location, "wb+") as file_obj:
            file_obj.write(await file.read())

        hash_sha256 = calcular_sha256_stream(location)
        tamano_bytes = os.path.getsize(location)

        evidencia = models.EvidenciaHash(
            predenuncia_id=reporte.id,
            nombre_archivo=file.filename,
            tipo_mime=file.content_type or "application/octet-stream",
            tamano_bytes=tamano_bytes,
            hash_sha256=hash_sha256
        )
        db.add(evidencia)

    db.commit()
    db.refresh(reporte)
    return reporte


# 2. Módulo de Verificación Policial (Auditoría Técnica en lugar de Triage)
@app.put("/api/verificacion-policial/validar/{reporte_id}")
def auditoria_tecnica_policial(reporte_id: str, db: Session = Depends(get_db)):
    """El oficial audita los metadatos y confirma la validez de las pruebas para activar los IoCs."""
    reporte = db.query(models.PreDenuncia).filter(models.PreDenuncia.id == reporte_id).first()
    if not reporte:
        raise HTTPException(status_code=404, detail="Reporte Digital no encontrado")

    reporte.estado_tramite = "AUDITADO_VALIDO"
    
    # Activar los indicadores de riesgo para consulta pública
    for ioc in reporte.iocs:
        ioc.estado_ioc = "ACTIVO"

    db.commit()
    return {
        "status": "éxito",
        "mensaje": "Auditoría completada. Reporte Digital validado e Indicadores (IoCs) activados preventivamente."
    }


# 3. Motor Preventivo Público de Consulta IoC
@app.post("/api/ioc/consultar", response_model=schemas.IoCSearchResponse)
def consultar_ioc_preventivo(payload: schemas.IoCSearchRequest, db: Session = Depends(get_db)):
    """Consulta binaria pública sin exponer identidades ni datos sensibles."""
    hash_consulta = anonimizar_ioc(payload.valor)
    
    coincidencia = db.query(models.IoCReportado).filter(
        models.IoCReportado.hash_ioc == hash_consulta,
        models.IoCReportado.estado_ioc == "ACTIVO"
    ).first()

    if coincidencia:
        return schemas.IoCSearchResponse(
            tipo_ioc=payload.tipo_ioc,
            registra_sospecha=True,
            mensaje="ALERTA PREVENTIVA: El dato consultado registra antecedentes de sospecha confirmados."
        )
    else:
        return schemas.IoCSearchResponse(
            tipo_ioc=payload.tipo_ioc,
            registra_sospecha=False,
            mensaje="SIN REGISTROS: El dato consultado no posee advertencias preventivas vigentes."
        )
