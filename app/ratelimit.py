"""Límite de solicitudes por clave (ventana deslizante, en memoria)."""
import time
from collections import defaultdict, deque


class LimitadorVentana:
    def __init__(self, maximo: int, segundos: int, reloj=time.monotonic):
        self.maximo, self.segundos, self.reloj = maximo, segundos, reloj
        self._eventos: dict[str, deque] = defaultdict(deque)

    def permitir(self, clave: str) -> bool:
        ahora = self.reloj()
        cola = self._eventos[clave]
        while cola and ahora - cola[0] >= self.segundos:
            cola.popleft()
        if len(cola) >= self.maximo:
            return False
        cola.append(ahora)
        return True

    def reiniciar(self) -> None:
        self._eventos.clear()
