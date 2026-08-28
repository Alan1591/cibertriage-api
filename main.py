import os
import sqlite3
from typing import List, Optional
from fastapi import FastAPI, Form, UploadFile, File, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Cibertriage API")

# Montar carpetas estáticas y de subidas
os.makedirs("uploads", exist_ok=True)
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

templates = Jinja2Templates(directory="templates")

# Inicialización de la Base de Datos
def init_db():
    conn = sqlite3.connect("cibertriage.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS denuncias (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT,
            dni TEXT,
            telefono TEXT,
            localidad TEXT,
            modalidad TEXT,
            monto REAL,
            descripcion TEXT,
            cbu_alias TEXT,
            tel_sospechoso TEXT,
            url_sospechosa TEXT,
            red_social TEXT,
            comisaria TEXT,
            provincia TEXT,
            latitud TEXT,
            longitud TEXT,
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Ruta Principal: Carga el Frontend
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Ruta para Recibir la Denuncia Digital
@app.post("/denuncia")
async def recibir_denuncia(
    nombre: str = Form(...),
    dni: str = Form(...),
    telefono: str = Form(...),
    localidad: str = Form(...),
    modalidad: str = Form(...),
    monto: Optional[float] = Form(0.0),
    descripcion: str = Form(...),
    cbu_alias: Optional[str] = Form(None),
    tel_sospechoso: Optional[str] = Form(None),
    url_sospechosa: Optional[str] = Form(None),
    red_social: Optional[str] = Form(None),
    comisaria: Optional[str] = Form("Denuncia Digital"),
    provincia: Optional[str] = Form("Entre Ríos"),
    latitud: Optional[str] = Form("-31.7317"),
    longitud: Optional[str] = Form("-60.5175"),
    file_dni: List[UploadFile] = File(None),
    file_selfie: Optional[UploadFile] = File(None),
    file_evidencia: List[UploadFile] = File(None)
):
    # Guardar archivos subidos
    def guardar_archivos(lista_archivos, prefijo):
        if not lista_archivos:
            return
        for file in lista_archivos:
            if file and file.filename:
                file_path = os.path.join("uploads", f"{prefijo}_{dni}_{file.filename}")
                with open(file_path, "wb") as f:
                    f.write(file.file.read())

    if file_dni:
        guardar_archivos(file_dni, "dni")
    if file_selfie and file_selfie.filename:
        guardar_archivos([file_selfie], "selfie")
    if file_evidencia:
        guardar_archivos(file_evidencia, "evidencia")

    # Insertar registros en SQLite
    conn = sqlite3.connect("cibertriage.db")
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO denuncias (
            nombre, dni, telefono, localidad, modalidad, monto, descripcion,
            cbu_alias, tel_sospechoso, url_sospechosa, red_social,
            comisaria, provincia, latitud, longitud
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        nombre, dni, telefono, localidad, modalidad, monto, descripcion,
        cbu_alias, tel_sospechoso, url_sospechosa, red_social,
        comisaria, provincia, latitud, longitud
    ))
    denuncia_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return JSONResponse(status_code=200, content={"status": "ok", "id": denuncia_id})
