"""Carga reportes FICTICIOS a una instancia en funcionamiento, usando la API pública
(pasan por la validación, el cifrado, el hash y la bitácora igual que uno real).

Uso:  python -m scripts.cargar_datos_ficticios URL [CANTIDAD]
Ej.:  python -m scripts.cargar_datos_ficticios http://127.0.0.1:8000 3
      python -m scripts.cargar_datos_ficticios https://proyectodenunciaonline.onrender.com 20

La API limita a 5 reportes cada 5 minutos por IP; el script espera y reintenta solo,
por lo que 20 reportes tardan unos 20 minutos. Todos los datos son inventados."""
import random
import sys
import time
import zlib
import struct

import httpx

TIPOLOGIAS = [
    "Phishing / Suplantación de Identidad", "Estafa en Compraventa Online",
    "Secuestro de Cuenta de WhatsApp", "Acceso No Autorizado a Homebanking",
    "Toma de Crédito Fraudulento", "Fraude con Tarjeta de Crédito / Débito",
    "Extorsión Digital / Ransomware", "Falsa Promesa de Inversiones / Cripto",
    "Venta de Productos Inexistentes", "Otras Modalidades Informáticas",
]
# Peso por tipología (para que el Pareto del documento sea verosímil)
PESOS = [24, 22, 12, 12, 8, 8, 4, 5, 3, 2]

RELATOS = {
    "Phishing / Suplantación de Identidad": "Recibí un mensaje que simulaba ser de mi banco con un enlace para 'verificar' mi cuenta. Ingresé mis datos y luego advertí movimientos que no reconozco.",
    "Estafa en Compraventa Online": "Pagué por transferencia un producto publicado en una red social. Tras el pago el vendedor dejó de responder y bloqueó mi contacto.",
    "Secuestro de Cuenta de WhatsApp": "Me pidieron un código que llegó por SMS y luego perdí el acceso a mi cuenta. Escribieron a mis contactos pidiendo dinero.",
    "Acceso No Autorizado a Homebanking": "Detecté transferencias desde mi homebanking que no realicé. Cambiaron mis credenciales sin mi autorización.",
    "Toma de Crédito Fraudulento": "Me notificaron un préstamo preaprobado que nunca solicité y el dinero fue transferido a una cuenta desconocida.",
    "Fraude con Tarjeta de Crédito / Débito": "Aparecieron consumos en comercios online que no reconozco en el resumen de mi tarjeta.",
    "Extorsión Digital / Ransomware": "Recibí un mensaje exigiendo un pago en criptomonedas bajo amenaza de difundir información de mis dispositivos.",
    "Falsa Promesa de Inversiones / Cripto": "Me ofrecieron una inversión con ganancias garantizadas en una plataforma. Deposité dinero y no pude retirarlo.",
    "Venta de Productos Inexistentes": "Compré pasajes en un sitio que luego dejó de funcionar. No recibí ningún comprobante válido.",
    "Otras Modalidades Informáticas": "Una persona se contactó por una aplicación de citas y, tras generar confianza, me pidió dinero para una supuesta emergencia.",
}

# Indicadores que se repiten en varios reportes (permiten demostrar la coincidencia entre casos)
ALIAS_REPETIDOS = ["estafa.demo.alfa", "cuenta.falsa.beta", "pago.rapido.gama"]
CBU_REPETIDOS = ["0000003100000000000011", "0000003100000000000022"]
URLS = ["banco-seguro-demo.example", "ofertas-cripto-demo.example", "pasajes-baratos-demo.example"]


def png_unico(n: int) -> bytes:
    """PNG válido de 1x1 píxel; el color depende de n para que cada hash sea distinto."""
    def trozo(tipo, datos):
        c = struct.pack(">I", len(datos)) + tipo + datos
        return c + struct.pack(">I", zlib.crc32(tipo + datos) & 0xFFFFFFFF)
    raw = b"\x00" + bytes([n % 256, (n * 7) % 256, (n * 13) % 256])
    return (b"\x89PNG\r\n\x1a\n" + trozo(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + trozo(b"IDAT", zlib.compress(raw)) + trozo(b"IEND", b""))


def pdf_unico(n: int) -> bytes:
    return (f"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            f"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n% captura ficticia {n}\n%%EOF\n").encode()


def armar(n: int, rnd: random.Random):
    tip = rnd.choices(TIPOLOGIAS, weights=PESOS)[0]
    datos = {
        "cuil_dni": f"2000000{n:04d}0", "nombre_apellido": f"Persona Ficticia {n:02d}",
        "telefono_contacto": f"34355500{n:02d}", "email": f"ficticio{n:02d}@example.com",
        "domicilio": "Calle Inventada 123, Paraná, Entre Ríos",
        "tipologia_delito": tip, "monto_estimado_ars": str(rnd.choice([15000, 40000, 85000, 120000, 250000, 480000])),
        "descripcion_hecho": f"[DATO FICTICIO] {RELATOS[tip]}",
        "consentimiento": "true",
    }
    # 1 a 2 indicadores por reporte; muchos se repiten a propósito
    opciones = [
        ("alias_sospechoso", rnd.choice(ALIAS_REPETIDOS)),
        ("cbu_cvu_sospechoso", rnd.choice(CBU_REPETIDOS)),
        ("telefono_sospechoso", f"11 5550-{rnd.randint(1000, 1005)}"),
        ("url_sitio_falso", rnd.choice(URLS)),
    ]
    for campo, valor in rnd.sample(opciones, rnd.choice([1, 2])):
        datos[campo] = valor
    archivos = []
    if rnd.random() < 0.7:
        archivos.append(("archivo", (f"captura_{n:02d}.png", png_unico(n), "image/png")))
    if rnd.random() < 0.3:
        archivos.append(("archivo", (f"comprobante_{n:02d}.pdf", pdf_unico(n), "application/pdf")))
    return datos, archivos


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    base = sys.argv[1].rstrip("/")
    cantidad = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    rnd = random.Random(2026)  # semilla fija: mismos datos si se repite
    ok = 0
    with httpx.Client(timeout=90) as c:
        for n in range(1, cantidad + 1):
            datos, archivos = armar(n, rnd)
            while True:
                r = c.post(f"{base}/api/reportes", data=datos, files=archivos or None)
                if r.status_code == 429:
                    print("  límite de solicitudes: espero 65 s…", flush=True)
                    time.sleep(65)
                    continue
                break
            if r.status_code == 201:
                ok += 1
                print(f"[{n:02d}/{cantidad}] {r.json()['ticket']}  {datos['tipologia_delito']}", flush=True)
            else:
                print(f"[{n:02d}/{cantidad}] ERROR {r.status_code}: {r.text[:200]}", flush=True)
    print(f"\nListo: {ok} de {cantidad} reportes ficticios cargados.")


if __name__ == "__main__":
    main()
