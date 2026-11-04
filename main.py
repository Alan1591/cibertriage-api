"""Compatibilidad: permite arrancar con `uvicorn main:app` (comando usado en Render hasta ahora).
Lo recomendado es `uvicorn app.wsgi:app`."""
from app.wsgi import app  # noqa: F401
