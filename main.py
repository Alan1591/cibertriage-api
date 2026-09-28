import os
import hashlib
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, HTTPException, status, Form, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from passlib.context import CryptContext

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

static_dir = os.path.join(BASE_DIR, "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

POLICE_USERS_DB = {
    "AlanYfran": {
        "legajo": "30689",
        "nombre": "Alan Yfran",
        "password_plain": "Alan2026!",
        "password_hash": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "rol": "Analista"
    },
    "LP-38491": {
        "legajo": "LP-38491",
        "nombre": "Oficial Principal",
        "password_plain": "CiberTriage2026",
        "password_hash": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "rol": "Analista_Triage"
    }
}

# Base de datos simulada en memoria para reportes
REPORTES_DB = []
ticket_counter = 892

class LoginSchema(BaseModel):
    usuario: str
    password: str

@app.get("/", response_class=FileResponse)
async def read_index():
    index_path = os.path.join(BASE_DIR, "templates", "index.html")
    if not os.path.exists(index_path):
        index_path = os.path.join(BASE_DIR, "index.html")
    
    if not os.path.exists(index_path):
        raise HTTPException(
            status_code=404,
            detail="Archivo index.html no encontrado en el servidor."
        )
    return FileResponse(index_path)

@app.post("/api/login")
async def login_policial(credentials: LoginSchema):
    user_key = next((k for k in POLICE_USERS_DB if k.lower() == credentials.usuario.strip().lower()), None)
    
    if not user_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Usuario '{credentials.usuario}' no encontrado"
        )
    
    user = POLICE_USERS_DB[user_key]
    
    password_ok = (credentials.password == user.get("password_plain"))
    if not password_ok:
        try:
            if pwd_context.verify(credentials.password, user.get("password_hash", "")):
                password_ok = True
        except Exception:
            pass
            
    if not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Contraseña incorrecta"
        )
    
    return {
        "status": "success",
        "message": "Autenticación correcta",
        "legajo": user["legajo"],
        "nombre": user["nombre"],
        "rol": user["rol"],
        "token": "session_token_cibertriage_2026_ok"
    }

# -------------------------------------------------------------------
# Guardar Pre-Denuncia y generar Hash SHA-256
# -------------------------------------------------------------------
@app.post("/api/reporte-digital")
async def recibir_reporte(
    nombre: Optional[str] = Form(None),
    dni: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    telefono: Optional[str] = Form(None),
    domicilio: Optional[str] = Form(None),
    tipologia: Optional[str] = Form(None),
    descripcion: Optional[str] = Form(None),
    monto: Optional[str] = Form(None),
    cbu_alias: Optional[str] = Form(None),
    archivo: Optional[List[UploadFile]] = File(None)
):
    global ticket_counter
    hashes = []

    if archivo:
        for f in archivo:
            if f.filename:
                contenido = await f.read()
                hashes.append(hashlib.sha256(contenido).hexdigest())

    if not hashes:
        data_string = f"{nombre}-{dni}-{tipologia}-{descripcion}"
        hashes.append(hashlib.sha256(data_string.encode('utf-8')).hexdigest())

    # Formatear el Ticket y guardar en memoria
    ticket_id = f"#TK-2026-{ticket_counter:04d}"
    ticket_counter += 1
    
    nuevo_reporte = {
        "ticket": ticket_id,
        "fecha": datetime.now().strftime("%d/%m/%Y"),
        "nombre": nombre or "Anónimo",
        "dni": dni or "N/A",
        "tipologia": tipologia or "Sin clasificar",
        "ioc": cbu_alias or telefono or "Sin datos",
        "hash": hashes[0] if len(hashes) == 1 else hashes[0],
        "descripcion": descripcion or ""
    }
    
    REPORTES_DB.append(nuevo_reporte)

    return {
        "status": "ok",
        "message": "Pre-denuncia registrada con éxito.",
        "ticket": ticket_id,
        "hash": nuevo_reporte["hash"]
    }

# -------------------------------------------------------------------
# Endpoint para listar Pre-Denuncias registradas en el Panel
# -------------------------------------------------------------------
@app.get("/api/reportes")
async def obtener_reportes():
    return {"status": "ok", "reportes": REPORTES_DB}
