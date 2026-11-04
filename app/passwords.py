"""Política de contraseñas y hash con bcrypt (con sal incorporada)."""
import re


class PoliticaError(ValueError):
    pass


def validar_politica(password: str) -> None:
    if len(password) < 8:
        raise PoliticaError("La contraseña debe tener al menos 8 caracteres")
    if len(password.encode("utf-8")) > 72:
        raise PoliticaError("La contraseña no puede superar 72 bytes")
    if not re.search(r"[a-z]", password):
        raise PoliticaError("Debe incluir una minúscula")
    if not re.search(r"[A-Z]", password):
        raise PoliticaError("Debe incluir una mayúscula")
    if not re.search(r"\d", password):
        raise PoliticaError("Debe incluir un número")
    if not re.search(r"[^A-Za-z0-9]", password):
        raise PoliticaError("Debe incluir un símbolo")


def hashear(password: str) -> str:
    import bcrypt
    validar_politica(password)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode()


# Hash válido de una contraseña aleatoria: se usa para igualar el tiempo de respuesta
# cuando el usuario no existe (evita enumerar usuarios por tiempos).
_HASH_FICTICIO = "$2b$12$C6UzMDM.H6dfI/f/IKcEeO3d1fQaYXG5oYhJX5gX7G3kq1w1Zk0yu"


def verificar(password: str, hash_guardado: str | None) -> bool:
    import bcrypt
    try:
        valido = bcrypt.checkpw(password.encode("utf-8")[:72], (hash_guardado or _HASH_FICTICIO).encode())
    except ValueError:
        return False
    return valido and hash_guardado is not None
