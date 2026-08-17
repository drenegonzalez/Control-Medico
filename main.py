import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# ==============================================================================
# CONFIGURACIÓN DE BASE DE DATOS (VERCEL POSTGRES / SQLITE LOCAL)
# ==============================================================================

# Vercel asigna automáticamente 'POSTGRES_URL' al vincular un Storage Postgres
DATABASE_URL = os.getenv("POSTGRES_URL") or os.getenv("DATABASE_URL")

if DATABASE_URL:
    # SQLAlchemy requiere el prefijo 'postgresql://' en lugar de 'postgres://'
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
else:
    # Fallback para desarrollo local con SQLite
    DATABASE_URL = "sqlite:///./control_medico.db"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()