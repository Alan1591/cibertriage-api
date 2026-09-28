from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from passlib.context import CryptContext

app = FastAPI()

# Configuración del hash de contraseñas (Bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Base de datos simulada de personal policial
POLICE_USERS_DB = {
    "LP-38491": {
        "legajo": "LP-38491",
        "nombre": "Oficial Principal",
        # Contraseña en texto plano para prueba: CiberTriage2026
        "password_hash": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "rol": "Analista_Triage"
    }
}

class LoginSchema(BaseModel):
    usuario: str
    password: str

@app.post("/api/login")
async def login_policial(credentials: LoginSchema):
    user = POLICE_USERS_DB.get(credentials.usuario)
    
    if not user or not pwd_context.verify(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales policiales inválidas o no autorizadas"
        )
    
    return {
        "status": "success",
        "message": "Autenticación correcta",
        "legajo": user["legajo"],
        "rol": user["rol"],
        "token": "session_token_cibertriage_2026_ok"
    }
