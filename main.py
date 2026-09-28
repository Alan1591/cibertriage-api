import os
import hashlib
from typing import Optional
from fastapi import FastAPI, HTTPException, status, Form, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from passlib.context import CryptContext

app = FastAPI()

# Directorio base absoluto
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Montar carpeta de archivos estáticos si existe
static_dir = os.path.join(BASE_DIR, "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Base de datos simulada
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

class LoginSchema(BaseModel):
    usuario: str
    password: str

# -------------------------------------------------------------------
# Ruta para servir el frontend (index.html)
# -------------------------------------------------------------------
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

# -------------------------------------------------------------------
# Endpoint de autenticación API
# -------------------------------------------------------------------
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
# Endpoint para recibir Pre-Denuncias Digitales y generar Hash SHA-256
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
    archivo: Optional[UploadFile] = File(None)
):
    # Calcular hash de la evidencia o del contenido del formulario
    if archivo:
        contenido = await archivo.read()
        sha256_hash = hashlib.sha256(contenido).hexdigest()
    else:
        # Si no adjuntó archivo, se genera un hash íntegro sobre la descripción
        data_string = f"{nombre}-{dni}-{descripcion}"
        sha256_hash = hashlib.sha256(data_string.encode('utf-8')).hexdigest()

    return {
        "status": "ok",
        "message": "Pre-denuncia registrada con éxito.",
        "hash": sha256_hash
    }
