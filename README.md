# CiberTriage – Prototipo (TFG, Lic. en Seguridad Informática)

Plataforma web para recibir reportes de fraude digital, preservar evidencia con huella SHA-256
y consultar indicadores (CBU/CVU, alias, teléfono, URL) sin exponer datos de las víctimas.

## Qué implementa (y qué NO)
| Función | Estado |
|---|---|
| Reporte ciudadano con adjuntos (PDF/imágenes validados por contenido, máx. 10 MB) | Implementado |
| SHA-256 de cada archivo al recibirlo; verificación al descargar | Implementado |
| Cifrado AES-256-GCM de relato, datos personales, indicadores y archivos | Implementado |
| Indicadores guardados como HMAC-SHA256; consulta pública devuelve solo «con registro de sospecha» o «sin registros» | Implementado |
| Login con bcrypt, JWT 15 min, refresh rotativo (8 h máx., 15 min inactividad), revocación, bloqueo tras 5 fallos | Implementado |
| Roles (`oficial_auditoria`, `administrador`) y bitácora encadenada con verificación | Implementado |
| Límite de solicitudes (en memoria, por IP) y cabeceras de seguridad | Implementado |
| App móvil (APK), Data Center Provincial, backups automáticos, TLS propio | **No incluido** (diseño propuesto en el documento; en la demo lo da el hosting) |

El hash prueba integridad respecto del momento de recepción; no prueba autenticidad del contenido
ni reemplaza una cadena de custodia completa.

## Ejecutar local
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env   # y completar; en desarrollo se pueden dejar vacías las claves
export ADMIN_USER=admin ADMIN_PASSWORD='Cambiar-Esta1!'   # Windows PowerShell: $env:ADMIN_USER=...
uvicorn app.wsgi:app --reload
pytest -v
```
Abrir http://127.0.0.1:8000. Usuarios nuevos: `python -m scripts.crear_usuario USUARIO "Nombre" oficial_auditoria`.

## Producción (Render)
1. Crear **PostgreSQL** en Render (plan pago o persistente) y copiar su `DATABASE_URL`.
2. Web Service: Build `pip install -r requirements.txt`; Start `uvicorn app.wsgi:app --host 0.0.0.0 --port $PORT`.
   Usar un plan que **no se duerma**.
3. Variables: `APP_ENV=prod`, `SECRET_KEY`, `ENCRYPTION_KEY` (guardar copia fuera de Render),
   `DATABASE_URL`, `ADMIN_USER`, `ADMIN_PASSWORD`, `TRUST_PROXY=1`.
4. Dominio: Settings → Custom Domains del servicio, y cargar en el proveedor del dominio el
   CNAME que indica Render. El certificado HTTPS se emite solo.
5. Antes de la defensa: cargar datos de prueba (ficticios) y probar login, reporte, consulta y descarga.

## Seguridad del repositorio
- Quitar `cibertriage.db` del historial y no volver a subir `.db`/`.env` (ver `.gitignore`).
- **Cambiar todas las contraseñas que estuvieron en el repo público**: se consideran comprometidas.
- Un solo proceso: el límite de solicitudes está en memoria (con varias instancias habría que usar Redis).
