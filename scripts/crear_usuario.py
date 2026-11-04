"""Crea un usuario del personal autorizado.
Uso:  python -m scripts.crear_usuario USUARIO "Nombre Apellido" oficial_auditoria|administrador
La contraseña se pide por teclado (no queda en el historial de la terminal)."""
import getpass
import sys

from app.config import load_settings
from app.database import Base, crear_fabrica, crear_motor
from app.models import Usuario
from app.passwords import hashear


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[3] not in ("oficial_auditoria", "administrador"):
        sys.exit(__doc__)
    usuario, nombre, rol = sys.argv[1].lower(), sys.argv[2], sys.argv[3]
    cfg = load_settings()
    motor = crear_motor(cfg.database_url)
    Base.metadata.create_all(motor)
    clave = getpass.getpass("Contraseña: ")
    if clave != getpass.getpass("Repetir: "):
        sys.exit("Las contraseñas no coinciden")
    with crear_fabrica(motor)() as db:
        if db.query(Usuario).filter_by(usuario=usuario).first():
            sys.exit("El usuario ya existe")
        db.add(Usuario(usuario=usuario, nombre=nombre, rol=rol, password_hash=hashear(clave)))
        db.commit()
    print(f"Usuario '{usuario}' creado con rol {rol}")


if __name__ == "__main__":
    main()
