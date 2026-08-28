import os
import hashlib
from typing import List, Optional
from datetime import datetime

from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

app = FastAPI(
    title="Sistema Unificado de Gestión de Ciberdelitos",
    description="API Backend para recepción de denuncias, triage policial y elevación judicial.",
    version="1.0.0"
)

# Directorios para guardar archivos subidos
UPLOAD_DIR = "uploads"
DNI_DIR = os.path.join(UPLOAD_DIR, "documentos_dni")
EVIDENCIA_DIR = os.path.join(UPLOAD_DIR, "evidencias_prueba")

os.makedirs(DNI_DIR, exist_ok=True)
os.makedirs(EVIDENCIA_DIR, exist_ok=True)

# Servir archivos estáticos (HTML, CSS, JS)
app.mount("/static", StaticFiles(directory="static"), name="static")


def guardar_archivo_con_hash(file: UploadFile, destino_folder: str):
    """
    Guarda un archivo subido en el disco y calcula su Hash SHA-256
    para preservar la cadena de custodia probatoria.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre_limpio = f"{timestamp}_{file.filename.replace(' ', '_')}"
    ruta_completa = os.path.join(destino_folder, nombre_limpio)

    sha256_hash = hashlib.sha256()
    
    with open(ruta_completa, "wb") as f:
        content = file.file.read()
        sha256_hash.update(content)
        f.write(content)

    return {
        "nombre_archivo": nombre_limpio,
        "ruta": ruta_completa,
        "hash_sha256": sha256_hash.hexdigest()
    }


@app.get("/")
async def serve_index():
    """Servir la página principal (Ventanas del Sistema)."""
    return FileResponse("templates/index.html")


@app.post("/api/denuncia")
async def registrar_denuncia(
    # Datos de la persona
    nombre: str = Form(...),
    dni: str = Form(...),
    tel_contacto: str = Form(...),
    localidad: str = Form(...),
    
    # Detalle del hecho
    modalidad: str = Form(...),
    monto: float = Form(0.0),
    comentario: str = Form(...),
    
    # Datos del sospechoso (Opcionales)
    cbu: Optional[str] = Form(None),
    alias: Optional[str] = Form(None),
    tel_estafador: Optional[str] = Form(None),
    url_falsa: Optional[str] = Form(None),
    red_social: Optional[str] = Form(None),
    
    # Geolocalización / Comisaría de origen
    comisaria: str = Form("Denuncia Digital Ciudadana"),
    provincia: str = Form("Entre Ríos"),
    lat: float = Form(-31.7317),
    lng: float = Form(-60.5175),
    
    # Archivos Adjuntos
    dni_adjuntos: List[UploadFile] = File(...),
    selfie_dni: UploadFile = File(...),
    archivos_prueba: List[UploadFile] = File(...)
):
    try:
        # 1. Procesar documentos de identidad (Frente/Dorso)
        documentos_procesados = []
        for doc in dni_adjuntos:
            res = guardar_archivo_con_hash(doc, DNI_DIR)
            documentos_procesados.append(res)

        # 2. Procesar Selfie con DNI
        selfie_procesada = guardar_archivo_con_hash(selfie_dni, DNI_DIR)

        # 3. Procesar evidencias y capturas de prueba
        evidencias_procesadas = []
        for prueba in archivos_prueba:
            res = guardar_archivo_con_hash(prueba, EVIDENCIA_DIR)
            evidencias_procesadas.append(res)

        # 4. Estructurar el expediente digital
        registro_denuncia = {
            "id_denuncia": f"DEN-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "fecha_registro": datetime.now().isoformat(),
            "denunciante": {
                "nombre": nombre,
                "dni": dni,
                "telefono": tel_contacto,
                "localidad": localidad,
                "identidad_validada": True,
                "adjuntos_dni": documentos_procesados,
                "selfie_dni": selfie_procesada
            },
            "hecho": {
                "modalidad": modalidad,
                "monto_perjuicio": monto,
                "relato": comentario,
                "geolocalizacion": {"lat": lat, "lng": lng, "provincia": provincia}
            },
            "indicadores_sospechoso": {
                "cbu_cvu": cbu,
                "alias": alias,
                "telefono": tel_estafador,
                "url": url_falsa,
                "red_social": red_social
            },
            "evidencias_digitales": evidencias_procesadas,
            "estado": "PENDIENTE_TRIAGE",
            "tramite_judicial": {
                "estado_judicial": "EN_ANALISIS_INICIAL",
                "elevado_fiscalia": False,
                "tiempo_elevacion_estimado": "60 minutos"
            }
        }

        # Acá podrías guardar 'registro_denuncia' en SQLite / PostgreSQL / Base de datos
        print(f"[NUEVA DENUNCIA REGISTRADA] ID: {registro_denuncia['id_denuncia']} - DNI: {dni}")

        return JSONResponse(
            status_code=201,
            content={
                "status": "exito",
                "mensaje": "Denuncia digital registrada con éxito.",
                "id_denuncia": registro_denuncia["id_denuncia"],
                "hash_selfie": selfie_procesada["hash_sha256"],
                "total_evidencias": len(evidencias_procesadas)
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar la denuncia: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)