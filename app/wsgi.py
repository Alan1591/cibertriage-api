"""Punto de entrada: uvicorn app.wsgi:app"""
from .main import create_app

app = create_app()
