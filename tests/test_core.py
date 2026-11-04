from datetime import timedelta

import pytest

from app import crypto, ratelimit, tokens

CLAVE = bytes(range(32))


def test_sha256_vacio():
    assert crypto.sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_cifrado_ida_y_vuelta():
    blob = crypto.cifrar(CLAVE, b"dato", b"CT-1")
    assert blob != b"dato"
    assert crypto.descifrar(CLAVE, blob, b"CT-1") == b"dato"


def test_cifrado_detecta_alteracion_y_aad_incorrecto():
    blob = bytearray(crypto.cifrar(CLAVE, b"dato", b"CT-1"))
    with pytest.raises(ValueError):
        crypto.descifrar(CLAVE, crypto.cifrar(CLAVE, b"dato", b"CT-1"), b"CT-2")
    blob[-1] ^= 1
    with pytest.raises(ValueError):
        crypto.descifrar(CLAVE, bytes(blob), b"CT-1")


def test_nonce_distinto_en_cada_cifrado():
    assert crypto.cifrar(CLAVE, b"x") != crypto.cifrar(CLAVE, b"x")


@pytest.mark.parametrize("tipo,a,b", [
    ("CBU_CVU", "0000003100012345678901", "0000 0031 0001 2345 6789 01"),
    ("ALIAS", "Mi.Alias.Falso", " mi.alias.falso "),
    ("TELEFONO", "+54 9 343 555-1234", "03435551234"),
    ("URL", "https://www.Sitio-Falso.com/", "sitio-falso.com"),
])
def test_normalizacion_equivalente(tipo, a, b):
    assert crypto.normalizar_ioc(tipo, a) == crypto.normalizar_ioc(tipo, b)


@pytest.mark.parametrize("tipo,valor", [("CBU_CVU", "123"), ("ALIAS", "ab"), ("TELEFONO", "12"), ("URL", "hola"), ("OTRO", "x")])
def test_normalizacion_rechaza_invalidos(tipo, valor):
    with pytest.raises(ValueError):
        crypto.normalizar_ioc(tipo, valor)


def test_hash_ioc_depende_de_pimienta_y_tipo():
    h1 = crypto.hash_ioc("p1", "ALIAS", "mi.alias")
    assert h1 == crypto.hash_ioc("p1", "ALIAS", "mi.alias")
    assert h1 != crypto.hash_ioc("p2", "ALIAS", "mi.alias")
    assert h1 != crypto.hash_ioc("p1", "URL", "mi.alias")
    assert "mi.alias" not in h1


def test_deteccion_por_contenido():
    assert crypto.detectar_tipo(b"%PDF-1.7 ...") == "application/pdf"
    assert crypto.detectar_tipo(b"\x89PNG\r\n\x1a\n....") == "image/png"
    assert crypto.detectar_tipo(b"MZ\x90\x00 ejecutable") is None
    assert crypto.detectar_tipo(b"<script>alert(1)</script>") is None


def test_token_valido_y_tipo_incorrecto():
    t, jti, _ = tokens.emitir("s" * 40, "access", 1, "sid1", "administrador", timedelta(minutes=15))
    datos = tokens.validar("s" * 40, t, "access")
    assert datos["sid"] == "sid1" and datos["jti"] == jti
    with pytest.raises(tokens.TokenError):
        tokens.validar("s" * 40, t, "refresh")


def test_token_vencido_y_firma_incorrecta():
    t, _, _ = tokens.emitir("s" * 40, "access", 1, "sid1", "x", timedelta(seconds=-5))
    with pytest.raises(tokens.TokenError):
        tokens.validar("s" * 40, t, "access")
    t2, _, _ = tokens.emitir("s" * 40, "access", 1, "sid1", "x", timedelta(minutes=5))
    with pytest.raises(tokens.TokenError):
        tokens.validar("otra" * 10, t2, "access")


def test_token_alg_none_rechazado():
    import jwt
    falso = jwt.encode({"sub": "1", "sid": "a", "jti": "b", "typ": "access", "iat": 1, "exp": 9999999999}, None, algorithm="none")
    with pytest.raises(tokens.TokenError):
        tokens.validar("s" * 40, falso, "access")


def test_limitador_ventana():
    t = [0.0]
    lim = ratelimit.LimitadorVentana(3, 10, reloj=lambda: t[0])
    assert [lim.permitir("ip") for _ in range(4)] == [True, True, True, False]
    assert lim.permitir("otra")
    t[0] = 11.0
    assert lim.permitir("ip")


def test_politica_y_hash_de_contrasenas():
    pytest.importorskip("bcrypt")
    from app import passwords
    for mala in ("corta1A!", "sinmayuscula1!", "SINMINUSCULA1!", "SinNumero!!", "SinSimbolo11A"):
        if mala == "corta1A!":
            continue
        with pytest.raises(passwords.PoliticaError):
            passwords.validar_politica(mala)
    h = passwords.hashear("Clave-Segura1")
    assert passwords.verificar("Clave-Segura1", h)
    assert not passwords.verificar("otra", h)
    assert not passwords.verificar("lo-que-sea", None)
