from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


def crear_motor(url: str):
    args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=args, pool_pre_ping=True)


def crear_fabrica(motor):
    return sessionmaker(bind=motor, autoflush=False, expire_on_commit=False)
