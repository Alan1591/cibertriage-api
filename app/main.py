"""CiberTriage - API y servidor web. Se crea con create_app() para poder probarla."""
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit, crypto, passwords, tokens
from .config import Settings, load_settings
from .database import Base, crear_fabrica, crear_motor
from .models import Evidencia, IoC, Reporte, Sesion, Usuario, ahora
from .ratelimit import LimitadorVentana

BASE = Path(__file__).resolve().parent.parent
TIPOLOGIAS = {
    'Phishing / Suplantación de Identidad',
    'Estafa en Compraventa Online',
    'Secuestro de Cuenta de WhatsApp',
    'Acceso No Autorizado a Homebanking',
    'Toma de Crédito Fraudulento',
    'Fraude con Tarjeta de Crédito / Débito',
    'Extorsión Digital / Ransomware',
    'Falsa Promesa de Inversiones / Cripto',
    'Venta de Productos Inexistentes',
    'Otras Modalidades Informáticas',
}


class Credenciales(BaseModel):
    usuario: str
    password: str


class RefreshIn(BaseModel):
    refresh_token: str


class ConsultaIn(BaseModel):
    tipo: str
    valor: str


def _utc(dt: datetime) -> datetime:
    """SQLite devuelve fechas sin zona; las tratamos como UTC."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or load_settings()
    motor = crear_motor(cfg.database_url)
    Sesionbd = crear_fabrica(motor)
    Base.metadata.create_all(motor)
    pimienta = hashlib.sha256(b"ioc-pepper|" + cfg.encryption_key).hexdigest()

    lim_login = LimitadorVentana(10, 60)
    lim_consulta = LimitadorVentana(30, 60)
    lim_reporte = LimitadorVentana(5, 300)

    app = FastAPI(title="CiberTriage", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = cfg
    app.state.limitadores = (lim_login, lim_consulta, lim_reporte)

    # ---------- utilidades ----------
    def get_db():
        db = Sesionbd()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def ip_de(request: Request) -> str:
        if cfg.trust_proxy:
            reenviado = request.headers.get("x-forwarded-for", "")
            if reenviado:
                return reenviado.split(",")[0].strip()[:64]
        return (request.client.host if request.client else "desconocida")[:64]

    def limitar(lim: LimitadorVentana, request: Request):
        if not lim.permitir(ip_de(request)):
            raise HTTPException(429, "Demasiadas solicitudes. Intente nuevamente en unos minutos.")

    def cifrar_json(obj, aad: bytes) -> bytes:
        return crypto.cifrar(cfg.encryption_key, json.dumps(obj, ensure_ascii=False).encode(), aad)

    def descifrar_json(blob: bytes, aad: bytes):
        return json.loads(crypto.descifrar(cfg.encryption_key, blob, aad))

    # ---------- autenticación ----------
    def usuario_actual(request: Request, db: Session = Depends(get_db)):
        cab = request.headers.get("authorization", "")
        if not cab.lower().startswith("bearer "):
            raise HTTPException(401, "No autenticado")
        try:
            datos = tokens.validar(cfg.secret_key, cab[7:], "access")
        except tokens.TokenError:
            raise HTTPException(401, "Sesión inválida o vencida")
        ses = db.get(Sesion, datos["sid"])
        ahora_ = ahora()
        if (not ses or ses.revocada or _utc(ses.expira) <= ahora_
                or ahora_ - _utc(ses.ultima_actividad) > timedelta(minutes=cfg.idle_minutes)):
            raise HTTPException(401, "Sesión vencida o revocada")
        if not ses.usuario.activo:
            raise HTTPException(401, "Usuario deshabilitado")
        ses.ultima_actividad = ahora_
        request.state.sid = ses.sid
        return ses.usuario

    def requiere(*roles):
        def dep(u: Usuario = Depends(usuario_actual)):
            if u.rol not in roles:
                raise HTTPException(403, "Permisos insuficientes")
            return u
        return dep

    def abrir_sesion(db: Session, u: Usuario, sid: str | None = None):
        sid = sid or secrets.token_hex(16)
        ses = db.get(Sesion, sid)
        refresh, jti, venc_ref = tokens.emitir(
            cfg.secret_key, "refresh", u.id, sid, u.rol, timedelta(hours=cfg.session_hours),
            ahora=ses.creada if ses else None)
        if ses is None:
            ses = Sesion(sid=sid, usuario_id=u.id, refresh_jti=jti, expira=venc_ref)
            db.add(ses)
        else:
            ses.refresh_jti = jti
        ses.ultima_actividad = ahora()
        acceso, _, _ = tokens.emitir(cfg.secret_key, "access", u.id, sid, u.rol,
                                     timedelta(minutes=cfg.access_minutes))
        return {"access_token": acceso, "refresh_token": refresh, "token_type": "bearer",
                "expira_en": cfg.access_minutes * 60, "usuario": u.nombre, "rol": u.rol}

    @app.post("/api/auth/login")
    def login(datos: Credenciales, request: Request, db: Session = Depends(get_db)):
        limitar(lim_login, request)
        ip = ip_de(request)
        u = db.scalar(select(Usuario).where(Usuario.usuario == datos.usuario.strip().lower()))
        if u and u.bloqueado_hasta and _utc(u.bloqueado_hasta) > ahora():
            audit.registrar(db, u.usuario, "LOGIN_BLOQUEADO", "", ip)
            db.commit()
            raise HTTPException(423, "Cuenta bloqueada temporalmente por intentos fallidos")
        ok = passwords.verificar(datos.password, u.password_hash if u else None) and bool(u and u.activo)
        if not ok:
            if u:
                u.intentos_fallidos += 1
                if u.intentos_fallidos >= cfg.max_login_failures:
                    u.bloqueado_hasta = ahora() + timedelta(minutes=cfg.lockout_minutes)
                    u.intentos_fallidos = 0
            audit.registrar(db, datos.usuario.strip().lower()[:60], "LOGIN_FALLIDO", "", ip)
            db.commit()
            raise HTTPException(401, "Credenciales inválidas")
        u.intentos_fallidos = 0
        u.bloqueado_hasta = None
        resp = abrir_sesion(db, u)
        audit.registrar(db, u.usuario, "LOGIN_OK", "", ip)
        return resp

    @app.post("/api/auth/refresh")
    def refrescar(datos: RefreshIn, request: Request, db: Session = Depends(get_db)):
        limitar(lim_login, request)
        try:
            t = tokens.validar(cfg.secret_key, datos.refresh_token, "refresh")
        except tokens.TokenError:
            raise HTTPException(401, "Sesión inválida o vencida")
        ses = db.get(Sesion, t["sid"])
        if not ses or ses.revocada:
            raise HTTPException(401, "Sesión revocada")
        if ses.refresh_jti != t["jti"]:  # reutilización de un refresh ya rotado
            ses.revocada = True
            audit.registrar(db, ses.usuario.usuario, "REFRESH_REUTILIZADO", "sesión revocada", ip_de(request))
            db.commit()
            raise HTTPException(401, "Sesión revocada")
        ahora_ = ahora()
        if (_utc(ses.expira) <= ahora_
                or ahora_ - _utc(ses.ultima_actividad) > timedelta(minutes=cfg.idle_minutes)
                or not ses.usuario.activo):
            raise HTTPException(401, "Sesión vencida")
        return abrir_sesion(db, ses.usuario, ses.sid)

    @app.post("/api/auth/logout")
    def logout(request: Request, u: Usuario = Depends(usuario_actual), db: Session = Depends(get_db)):
        ses = db.get(Sesion, request.state.sid)
        ses.revocada = True
        audit.registrar(db, u.usuario, "LOGOUT", "", ip_de(request))
        return {"ok": True}

    # ---------- público ----------
    @app.post("/api/reportes", status_code=201)
    async def crear_reporte(
        request: Request,
        cuil_dni: str = Form(...), nombre_apellido: str = Form(...),
        telefono_contacto: str = Form(""), email: str = Form(""), domicilio: str = Form(""),
        tipologia_delito: str = Form(...), monto_estimado_ars: str = Form(""),
        descripcion_hecho: str = Form(...),
        cbu_cvu_sospechoso: str = Form(""), alias_sospechoso: str = Form(""),
        telefono_sospechoso: str = Form(""), url_sitio_falso: str = Form(""),
        archivo: list[UploadFile] = File(default=[]),
        db: Session = Depends(get_db),
    ):
        limitar(lim_reporte, request)
        if tipologia_delito not in TIPOLOGIAS:
            raise HTTPException(422, "Tipología no válida")
        if not (10 <= len(descripcion_hecho.strip()) <= 5000):
            raise HTTPException(422, "El relato debe tener entre 10 y 5000 caracteres")
        if not nombre_apellido.strip() or not cuil_dni.strip():
            raise HTTPException(422, "Datos del denunciante incompletos")
        monto = None
        if monto_estimado_ars.strip():
            try:
                monto = int(float(monto_estimado_ars.replace(",", ".")))
                if monto < 0:
                    raise ValueError
            except ValueError:
                raise HTTPException(422, "Monto inválido")

        indicadores = []
        for tipo, valor in (("CBU_CVU", cbu_cvu_sospechoso), ("ALIAS", alias_sospechoso),
                            ("TELEFONO", telefono_sospechoso), ("URL", url_sitio_falso)):
            if valor.strip():
                try:
                    indicadores.append((tipo, crypto.normalizar_ioc(tipo, valor)))
                except ValueError as exc:
                    raise HTTPException(422, str(exc))

        archivos = [a for a in archivo if a.filename]
        if len(archivos) > cfg.max_files:
            raise HTTPException(422, f"Máximo {cfg.max_files} archivos")
        evidencias = []
        for a in archivos:
            contenido = await a.read(cfg.max_file_bytes + 1)
            if len(contenido) > cfg.max_file_bytes:
                raise HTTPException(413, f"'{a.filename}' supera el máximo de {cfg.max_file_bytes // 1048576} MB")
            mime = crypto.detectar_tipo(contenido)
            if not mime:
                raise HTTPException(415, f"'{a.filename}': solo se aceptan PDF e imágenes (PNG, JPG, GIF, WEBP)")
            evidencias.append((a.filename[:200], mime, contenido))

        ticket = f"CT-{ahora().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
        aad = ticket.encode()
        rep = Reporte(
            ticket=ticket, tipologia=tipologia_delito, monto_ars=monto,
            relato_cifrado=crypto.cifrar(cfg.encryption_key, descripcion_hecho.strip().encode(), aad),
            denunciante_cifrado=cifrar_json({
                "cuil_dni": cuil_dni.strip(), "nombre_apellido": nombre_apellido.strip(),
                "telefono": telefono_contacto.strip(), "email": email.strip(),
                "domicilio": domicilio.strip()}, aad),
        )
        for tipo, norm in indicadores:
            rep.iocs.append(IoC(tipo=tipo, hash_ioc=crypto.hash_ioc(pimienta, tipo, norm),
                                valor_cifrado=crypto.cifrar(cfg.encryption_key, norm.encode(), aad)))
        for nombre, mime, contenido in evidencias:
            rep.evidencias.append(Evidencia(
                nombre_original=nombre, mime=mime, tamano=len(contenido),
                sha256=crypto.sha256_hex(contenido),
                contenido_cifrado=crypto.cifrar(cfg.encryption_key, contenido, aad)))
        db.add(rep)
        audit.registrar(db, "ciudadano", "REPORTE_RECIBIDO",
                        f"{ticket}; iocs={len(indicadores)}; evidencias={len(evidencias)}", ip_de(request))
        return {"ticket": ticket, "evidencias": [
            {"nombre": n, "sha256": crypto.sha256_hex(c)} for n, _, c in evidencias]}

    @app.post("/api/consulta-ioc")
    def consulta_ioc(datos: ConsultaIn, request: Request, db: Session = Depends(get_db)):
        limitar(lim_consulta, request)
        try:
            norm = crypto.normalizar_ioc(datos.tipo, datos.valor)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        h = crypto.hash_ioc(pimienta, datos.tipo, norm)
        # Solo cuentan los reportes revisados y aprobados por personal autorizado (el aprobador queda en la
        # bitácora); un reporte pendiente o desestimado no activa el indicador. Volver el estado a
        # "desestimado" (rectificación) lo da de baja de la consulta de inmediato.
        cantidad = db.scalar(select(func.count(func.distinct(IoC.reporte_id)))
                             .select_from(IoC).join(Reporte, Reporte.id == IoC.reporte_id)
                             .where(IoC.hash_ioc == h, Reporte.estado == "aprobado")) or 0
        # Respuesta pública binaria: no revela cantidades, datos de reportes ni del denunciante.
        con_registro = cantidad > 0
        return {"tipo": datos.tipo, "con_registro": con_registro,
                "resultado": "CON REGISTRO DE SOSPECHA" if con_registro else "SIN REGISTROS",
                "mensaje": ("El indicador consultado figura en reportes recibidos. Evite operar con él."
                            if con_registro else
                            "No figura en los reportes recibidos. Esto no garantiza que sea seguro.")}

    # ---------- personal autorizado ----------
    rol_ver = requiere("oficial_auditoria", "administrador")

    @app.get("/api/reportes")
    def listar(u: Usuario = Depends(rol_ver), db: Session = Depends(get_db)):
        filas = db.scalars(select(Reporte).order_by(Reporte.id.desc()).limit(200)).all()
        return [{"id": r.id, "ticket": r.ticket, "fecha": _utc(r.fecha).isoformat(),
                 "tipologia": r.tipologia, "monto_ars": r.monto_ars, "estado": r.estado,
                 "evidencias": len(r.evidencias), "indicadores": len(r.iocs)} for r in filas]

    @app.get("/api/reportes/{rid}")
    def detalle(rid: int, request: Request, u: Usuario = Depends(rol_ver), db: Session = Depends(get_db)):
        r = db.get(Reporte, rid)
        if not r:
            raise HTTPException(404, "Reporte inexistente")
        aad = r.ticket.encode()
        audit.registrar(db, u.usuario, "REPORTE_CONSULTADO", r.ticket, ip_de(request))
        return {
            "id": r.id, "ticket": r.ticket, "fecha": _utc(r.fecha).isoformat(),
            "tipologia": r.tipologia, "monto_ars": r.monto_ars, "estado": r.estado,
            "relato": crypto.descifrar(cfg.encryption_key, r.relato_cifrado, aad).decode(),
            "denunciante": descifrar_json(r.denunciante_cifrado, aad),
            "indicadores": [{"tipo": i.tipo, "valor": crypto.descifrar(cfg.encryption_key, i.valor_cifrado, aad).decode(),
                             "hash": i.hash_ioc} for i in r.iocs],
            "evidencias": [{"id": e.id, "nombre": e.nombre_original, "mime": e.mime,
                            "tamano": e.tamano, "sha256": e.sha256} for e in r.evidencias],
        }

    class EstadoIn(BaseModel):
        estado: str

    @app.patch("/api/reportes/{rid}/estado")
    def cambiar_estado(rid: int, datos: EstadoIn, request: Request,
                       u: Usuario = Depends(rol_ver), db: Session = Depends(get_db)):
        if datos.estado not in ("pendiente", "aprobado", "desestimado"):
            raise HTTPException(422, "Estado inválido")
        r = db.get(Reporte, rid)
        if not r:
            raise HTTPException(404, "Reporte inexistente")
        anterior, r.estado = r.estado, datos.estado
        audit.registrar(db, u.usuario, "ESTADO_CAMBIADO", f"{r.ticket}; {anterior}->{datos.estado}", ip_de(request))
        return {"id": r.id, "estado": r.estado}

    @app.get("/api/evidencias/{eid}/descargar")
    def descargar(eid: int, request: Request, u: Usuario = Depends(rol_ver), db: Session = Depends(get_db)):
        e = db.get(Evidencia, eid)
        if not e:
            raise HTTPException(404, "Evidencia inexistente")
        r = db.get(Reporte, e.reporte_id)
        try:
            contenido = crypto.descifrar(cfg.encryption_key, e.contenido_cifrado, r.ticket.encode())
        except ValueError:
            audit.registrar(db, u.usuario, "EVIDENCIA_ALTERADA", f"{r.ticket}; id={eid}", ip_de(request))
            db.commit()
            raise HTTPException(409, "La evidencia almacenada no supera la verificación de integridad")
        integra = crypto.comparar_seguro(crypto.sha256_hex(contenido), e.sha256)
        audit.registrar(db, u.usuario, "EVIDENCIA_DESCARGADA",
                        f"{r.ticket}; id={eid}; integridad={'OK' if integra else 'FALLA'}", ip_de(request))
        if not integra:
            db.commit()
            raise HTTPException(409, "El hash SHA-256 actual no coincide con el registrado al recibir el archivo")
        return Response(contenido, media_type=e.mime, headers={
            "Content-Disposition": f'attachment; filename="evidencia_{eid}"',
            "X-SHA256": e.sha256})

    @app.get("/api/indicadores")
    def indicadores(u: Usuario = Depends(rol_ver), db: Session = Depends(get_db)):
        por_tipologia = dict(db.execute(select(Reporte.tipologia, func.count()).group_by(Reporte.tipologia)).all())
        repetidos = db.execute(
            select(IoC.tipo, func.count()).where(IoC.hash_ioc.in_(
                select(IoC.hash_ioc).group_by(IoC.hash_ioc).having(func.count(func.distinct(IoC.reporte_id)) > 1)
            )).group_by(IoC.tipo)).all()
        return {"total_reportes": db.scalar(select(func.count()).select_from(Reporte)) or 0,
                "monto_total_ars": db.scalar(select(func.coalesce(func.sum(Reporte.monto_ars), 0))) or 0,
                "por_tipologia": por_tipologia,
                "indicadores_en_multiples_reportes": {t: n for t, n in repetidos}}

    @app.get("/api/auditoria")
    def ver_auditoria(u: Usuario = Depends(requiere("administrador")), db: Session = Depends(get_db)):
        filas = db.scalars(select(audit.Auditoria).order_by(audit.Auditoria.id.desc()).limit(200)).all()
        return {"verificacion": audit.verificar_cadena(db),
                "registros": [{"id": a.id, "fecha": a.fecha.isoformat(), "actor": a.actor,
                               "accion": a.accion, "detalle": a.detalle, "ip": a.ip} for a in filas]}

    # ---------- cabeceras de seguridad y estáticos ----------
    @app.middleware("http")
    async def cabeceras(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
                                        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                                        "img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                                        "frame-ancestors 'none'"),
        })
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/health")
    def health(db: Session = Depends(get_db)):
        db.execute(select(1))
        return {"estado": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def inicio():
        return FileResponse(BASE / "templates" / "index.html")

    app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

    # ---------- usuario administrador inicial ----------
    if cfg.admin_user and cfg.admin_password:
        with Sesionbd() as db:
            if not db.scalar(select(Usuario).where(Usuario.usuario == cfg.admin_user.lower())):
                db.add(Usuario(usuario=cfg.admin_user.lower(), nombre=cfg.admin_name,
                               password_hash=passwords.hashear(cfg.admin_password), rol="administrador"))
                db.commit()
    return app
