"""Pruebas de extremo a extremo (requieren las dependencias de requirements.txt)."""
import json
from datetime import timedelta

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("bcrypt")
pytest.importorskip("multipart")
from fastapi.testclient import TestClient  # noqa: E402

from app import crypto  # noqa: E402
from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Evidencia  # noqa: E402

PASS = "Admin-Seguro1"
PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 64


@pytest.fixture()
def cliente(tmp_path):
    cfg = Settings(database_url=f"sqlite:///{tmp_path/'t.db'}", secret_key="k" * 40,
                   encryption_key=bytes(range(32)), admin_user="admin", admin_password=PASS)
    app = create_app(cfg)
    with TestClient(app) as c:
        c.app_ = app
        yield c


def datos(**extra):
    base = {"cuil_dni": "20123456786", "nombre_apellido": "Ana Pérez", "tipologia_delito": "Phishing / Suplantación de Identidad",
            "descripcion_hecho": "Me estafaron con un link falso de banco.", "alias_sospechoso": "cuenta.falsa.mp"}
    base.update(extra)
    return base


def login(c, password=PASS):
    return c.post("/api/auth/login", json={"usuario": "admin", "password": password})


def auth(c):
    t = login(c).json()["access_token"]
    return {"Authorization": f"Bearer {t}"}


def test_health_y_cabeceras(cliente):
    r = cliente.get("/health")
    assert r.status_code == 200 and r.headers["x-content-type-options"] == "nosniff"


def test_reporte_y_consulta_publica_sin_filtrar_datos(cliente):
    r = cliente.post("/api/reportes", data=datos(), files={"archivo": ("p.png", PNG, "image/png")})
    assert r.status_code == 201, r.text
    assert r.json()["evidencias"][0]["sha256"] == crypto.sha256_hex(PNG)
    consulta = {"tipo": "ALIAS", "valor": "CUENTA.falsa.mp"}
    # pendiente de revisión: el indicador todavía NO está activo
    assert cliente.post("/api/consulta-ioc", json=consulta).json()["con_registro"] is False
    h = auth(cliente)
    rid = cliente.get("/api/reportes", headers=h).json()[0]["id"]
    cliente.patch(f"/api/reportes/{rid}/estado", json={"estado": "aprobado"}, headers=h)
    c = cliente.post("/api/consulta-ioc", json=consulta)
    assert c.json()["con_registro"] is True and c.json()["resultado"] == "CON REGISTRO DE SOSPECHA"
    assert "coincidencias" not in c.json()  # la respuesta pública no revela cantidades
    assert "Ana" not in c.text and "20123456786" not in c.text
    sin = cliente.post("/api/consulta-ioc", json={"tipo": "ALIAS", "valor": "otro.alias.x"}).json()
    assert sin["con_registro"] is False and sin["resultado"] == "SIN REGISTROS"
    # rectificación: al desestimar el reporte, el indicador se da de baja
    cliente.patch(f"/api/reportes/{rid}/estado", json={"estado": "desestimado"}, headers=h)
    assert cliente.post("/api/consulta-ioc", json=consulta).json()["con_registro"] is False
    acciones = [a["accion"] for a in cliente.get("/api/auditoria", headers=h).json()["registros"]]
    assert acciones.count("ESTADO_CAMBIADO") == 2


def test_rechaza_archivo_disfrazado(cliente):
    r = cliente.post("/api/reportes", data=datos(), files={"archivo": ("virus.pdf", b"MZ\x90\x00", "application/pdf")})
    assert r.status_code == 415


def test_rechaza_ioc_invalido_y_tipologia_invalida(cliente):
    assert cliente.post("/api/reportes", data=datos(cbu_cvu_sospechoso="123")).status_code == 422
    assert cliente.post("/api/reportes", data=datos(tipologia_delito="X")).status_code == 422


def test_endpoints_protegidos(cliente):
    for ruta in ("/api/reportes", "/api/indicadores", "/api/auditoria"):
        assert cliente.get(ruta).status_code == 401


def test_datos_personales_cifrados_en_base(cliente):
    cliente.post("/api/reportes", data=datos())
    from sqlalchemy import text
    from app.database import crear_motor
    with crear_motor(cliente.app_.state.settings.database_url).connect() as cx:
        crudo = cx.execute(text("select denunciante_cifrado, relato_cifrado from reportes")).one()
    assert b"Ana" not in crudo[0] and b"estafaron" not in crudo[1]


def test_flujo_personal_detalle_y_descarga(cliente):
    cliente.post("/api/reportes", data=datos(), files={"archivo": ("p.png", PNG, "image/png")})
    h = auth(cliente)
    lista = cliente.get("/api/reportes", headers=h).json()
    d = cliente.get(f"/api/reportes/{lista[0]['id']}", headers=h).json()
    assert d["denunciante"]["nombre_apellido"] == "Ana Pérez" and d["indicadores"][0]["valor"] == "cuenta.falsa.mp"
    f = cliente.get(f"/api/evidencias/{d['evidencias'][0]['id']}/descargar", headers=h)
    assert f.status_code == 200 and f.content == PNG
    assert cliente.patch(f"/api/reportes/{d['id']}/estado", json={"estado": "aprobado"}, headers=h).json()["estado"] == "aprobado"


def test_evidencia_manipulada_en_base_es_detectada(cliente):
    cliente.post("/api/reportes", data=datos(), files={"archivo": ("p.png", PNG, "image/png")})
    h = auth(cliente)
    from sqlalchemy.orm import Session
    from app.database import crear_motor
    with Session(crear_motor(cliente.app_.state.settings.database_url)) as s:
        e = s.query(Evidencia).one()
        e.contenido_cifrado = e.contenido_cifrado[:-1] + bytes([e.contenido_cifrado[-1] ^ 1])
        s.commit()
        eid = e.id
    assert cliente.get(f"/api/evidencias/{eid}/descargar", headers=h).status_code == 409


def test_bloqueo_tras_intentos_fallidos(cliente):
    for _ in range(5):
        assert login(cliente, "mala").status_code == 401
    assert login(cliente).status_code == 423  # bloqueada aunque la clave sea correcta


def test_logout_revoca_sesion(cliente):
    h = auth(cliente)
    assert cliente.get("/api/reportes", headers=h).status_code == 200
    cliente.post("/api/auth/logout", headers=h)
    assert cliente.get("/api/reportes", headers=h).status_code == 401


def test_refresh_rota_y_detecta_reutilizacion(cliente):
    d = login(cliente).json()
    r1 = cliente.post("/api/auth/refresh", json={"refresh_token": d["refresh_token"]})
    assert r1.status_code == 200
    r2 = cliente.post("/api/auth/refresh", json={"refresh_token": d["refresh_token"]})  # token viejo
    assert r2.status_code == 401
    nuevo = {"Authorization": f"Bearer {r1.json()['access_token']}"}
    assert cliente.get("/api/reportes", headers=nuevo).status_code == 401  # sesión revocada por reutilización


def test_inactividad_vence_la_sesion(cliente):
    from datetime import datetime, timezone
    from sqlalchemy.orm import Session
    from app.database import crear_motor
    from app.models import Sesion
    h = auth(cliente)
    with Session(crear_motor(cliente.app_.state.settings.database_url)) as s:
        ses = s.query(Sesion).one()
        ses.ultima_actividad = datetime.now(timezone.utc) - timedelta(minutes=16)
        s.commit()
    assert cliente.get("/api/reportes", headers=h).status_code == 401


def test_bitacora_encadenada_integra_y_detecta_cambios(cliente):
    cliente.post("/api/reportes", data=datos())
    h = auth(cliente)
    assert cliente.get("/api/auditoria", headers=h).json()["verificacion"]["integra"] is True
    from sqlalchemy import text
    from app.database import crear_motor
    with crear_motor(cliente.app_.state.settings.database_url).begin() as cx:
        cx.execute(text("update auditoria set detalle='alterado' where id=1"))
    assert cliente.get("/api/auditoria", headers=h).json()["verificacion"]["integra"] is False
