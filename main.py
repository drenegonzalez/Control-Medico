from datetime import datetime, timedelta, timezone
import enum
from typing import List, Optional
import os

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, ConfigDict
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Enum as SQLEnum, ForeignKey, Text, or_
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from passlib.context import CryptContext
import jwt

# ==============================================================================
# CONFIGURACIÓN DE BASE DE DATOS (VERCEL POSTGRES / SQLITE LOCAL)
# ==============================================================================

DATABASE_URL = os.getenv("POSTGRES_URL") or os.getenv("DATABASE_URL")

if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
else:
    DATABASE_URL = "sqlite:///./control_medico.db"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = os.getenv("SECRET_KEY", "CLAVE_SECRETA_SUPER_SEGURA_CAMBIAR_EN_PRODUCCION")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==============================================================================
# MODELOS DE BASE DE DATOS
# ==============================================================================

class RolUsuario(str, enum.Enum):
    ADMIN = "administrador"
    MEDICO = "medico"
    NUTRICIONISTA = "nutricionista"

class EstadoCita(str, enum.Enum):
    PROGRAMADA = "programada"
    COMPLETADA = "completada"
    CANCELADA = "cancelada"

class UsuarioDB(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    rol = Column(SQLEnum(RolUsuario), nullable=False)
    fecha_creacion = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class PacienteDB(Base):
    __tablename__ = "pacientes"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, nullable=False)
    edad = Column(Integer, nullable=False)
    telefono = Column(String, nullable=False)
    antecedentes_medicos = Column(Text, nullable=True)
    fecha_registro = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class CitaDB(Base):
    __tablename__ = "citas"

    id = Column(Integer, primary_key=True, index=True)
    paciente_id = Column(Integer, ForeignKey("pacientes.id"), nullable=False)
    profesional_id = Column(Integer, ForeignKey("usuarios.id"), nullable=False)
    fecha_hora = Column(DateTime, nullable=False)
    motivo = Column(String, nullable=False)
    estado = Column(SQLEnum(EstadoCita), default=EstadoCita.PROGRAMADA)
    diagnostico = Column(Text, nullable=True)
    tratamiento = Column(Text, nullable=True)
    plan_nutricional = Column(Text, nullable=True)

    paciente = relationship("PacienteDB")
    profesional = relationship("UsuarioDB")

Base.metadata.create_all(bind=engine)

# ==============================================================================
# ESQUEMAS PYDANTIC
# ==============================================================================

class Token(BaseModel):
    access_token: str
    token_type: str

class UsuarioCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    rol: RolUsuario

class UsuarioOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    rol: RolUsuario
    model_config = ConfigDict(from_attributes=True)

class PacienteCreate(BaseModel):
    nombre: str
    edad: int
    telefono: str
    antecedentes_medicos: Optional[str] = None

class PacienteOut(BaseModel):
    id: int
    nombre: str
    edad: int
    telefono: str
    antecedentes_medicos: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class AntecedentesUpdate(BaseModel):
    antecedentes_medicos: str

class CitaCreate(BaseModel):
    paciente_id: int
    profesional_id: int
    fecha_hora: datetime
    motivo: str

class CitaOut(BaseModel):
    id: int
    paciente_id: int
    profesional_id: int
    nombre_paciente: str
    nombre_profesional: str
    rol_profesional: str
    fecha_hora: datetime
    motivo: str
    estado: EstadoCita
    diagnostico: Optional[str] = None
    tratamiento: Optional[str] = None
    plan_nutricional: Optional[str] = None

class AtencionMedica(BaseModel):
    diagnostico: str
    tratamiento: str

class AtencionNutricional(BaseModel):
    plan_nutricional: str

# ==============================================================================
# FUNCIONES AUXILIARES
# ==============================================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UsuarioDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    usuario = db.query(UsuarioDB).filter(UsuarioDB.username == username).first()
    if usuario is None:
        raise credentials_exception
    return usuario

def verificar_roles(roles_permitidos: List[RolUsuario]):
    def rol_checker(usuario: UsuarioDB = Depends(get_current_user)):
        if usuario.rol not in roles_permitidos:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permisos suficientes para esta operación."
            )
        return usuario
    return rol_checker

# ==============================================================================
# FASTAPI APP Y RUTAS
# ==============================================================================

app = FastAPI(title="Sistema de Control Médico y Nutricional")

@app.on_event("startup")
def startup_db():
    db = SessionLocal()
    try:
        if not db.query(UsuarioDB).first():
            usuarios_iniciales = [
                UsuarioDB(username="admin", email="admin@hospital.com", hashed_password=hash_password("admin123"), rol=RolUsuario.ADMIN),
                UsuarioDB(username="doc_perez", email="perez@hospital.com", hashed_password=hash_password("doc123"), rol=RolUsuario.MEDICO),
                UsuarioDB(username="nutri_gomez", email="gomez@hospital.com", hashed_password=hash_password("nutri123"), rol=RolUsuario.NUTRICIONISTA),
            ]
            db.add_all(usuarios_iniciales)
            db.commit()
    finally:
        db.close()

@app.get("/", tags=["General"])
def servir_frontend():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"mensaje": "El archivo index.html no existe."}

@app.post("/token", response_model=Token, tags=["Autenticación"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    usuario = db.query(UsuarioDB).filter(UsuarioDB.username == form_data.username).first()
    if not usuario or not verify_password(form_data.password, usuario.hashed_password):
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")
    access_token = create_access_token(data={"sub": usuario.username, "rol": usuario.rol})
    return {"access_token": access_token, "token_type": "bearer"}

# --- PROFESIONALES ---
@app.get("/profesionales", response_model=List[UsuarioOut], tags=["Profesionales"])
def listar_profesionales(
    rol: Optional[RolUsuario] = None,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(get_current_user)
):
    query = db.query(UsuarioDB)
    if rol:
        query = query.filter(UsuarioDB.rol == rol)
    else:
        query = query.filter(UsuarioDB.rol.in_([RolUsuario.MEDICO, RolUsuario.NUTRICIONISTA]))
    return query.all()

# --- PACIENTES ---
@app.get("/pacientes", response_model=List[PacienteOut], tags=["Pacientes"])
def listar_pacientes(
    buscar: Optional[str] = None,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(get_current_user)
):
    query = db.query(PacienteDB)
    if buscar:
        query = query.filter(
            or_(
                PacienteDB.nombre.ilike(f"%{buscar}%"),
                PacienteDB.telefono.ilike(f"%{buscar}%")
            )
        )
    return query.all()

@app.get("/pacientes/{paciente_id}/historial", response_model=List[CitaOut], tags=["Pacientes"])
def obtener_historial_paciente(
    paciente_id: int,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(get_current_user)
):
    paciente = db.query(PacienteDB).filter(PacienteDB.id == paciente_id).first()
    if not paciente:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")

    citas = db.query(CitaDB).filter(CitaDB.paciente_id == paciente_id).order_by(CitaDB.fecha_hora.desc()).all()
    
    resultado = []
    for c in citas:
        resultado.append(CitaOut(
            id=c.id,
            paciente_id=c.paciente_id,
            profesional_id=c.profesional_id,
            nombre_paciente=c.paciente.nombre if c.paciente else "N/A",
            nombre_profesional=c.profesional.username if c.profesional else "N/A",
            rol_profesional=c.profesional.rol.value if c.profesional else "N/A",
            fecha_hora=c.fecha_hora,
            motivo=c.motivo,
            estado=c.estado,
            diagnostico=c.diagnostico,
            tratamiento=c.tratamiento,
            plan_nutricional=c.plan_nutricional
        ))
    return resultado

@app.post("/pacientes", response_model=PacienteOut, tags=["Pacientes"])
def crear_paciente(
    paciente: PacienteCreate,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(verificar_roles([RolUsuario.ADMIN, RolUsuario.MEDICO]))
):
    nuevo_paciente = PacienteDB(**paciente.model_dump())
    db.add(nuevo_paciente)
    db.commit()
    db.refresh(nuevo_paciente)
    return nuevo_paciente

@app.post("/pacientes/{paciente_id}/antecedentes", response_model=PacienteOut, tags=["Pacientes"])
def actualizar_antecedentes(
    paciente_id: int,
    data: AntecedentesUpdate,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(get_current_user)
):
    paciente = db.query(PacienteDB).filter(PacienteDB.id == paciente_id).first()
    if not paciente:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")
    
    registro = f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {data.antecedentes_medicos}"
    paciente.antecedentes_medicos = f"{paciente.antecedentes_medicos or ''}\n{registro}".strip()
    db.commit()
    db.refresh(paciente)
    return paciente

# --- CITAS ---
@app.get("/citas", response_model=List[CitaOut], tags=["Citas"])
def listar_citas(
    buscar: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: UsuarioDB = Depends(get_current_user)
):
    query = db.query(CitaDB)
    
    if current_user.rol in [RolUsuario.MEDICO, RolUsuario.NUTRICIONISTA]:
        query = query.filter(CitaDB.profesional_id == current_user.id)
        
    if buscar:
        query = query.filter(CitaDB.motivo.ilike(f"%{buscar}%"))
        
    citas = query.order_by(CitaDB.fecha_hora.desc()).all()
    
    resultado = []
    for c in citas:
        resultado.append(CitaOut(
            id=c.id,
            paciente_id=c.paciente_id,
            profesional_id=c.profesional_id,
            nombre_paciente=c.paciente.nombre if c.paciente else "N/A",
            nombre_profesional=c.profesional.username if c.profesional else "N/A",
            rol_profesional=c.profesional.rol.value if c.profesional else "N/A",
            fecha_hora=c.fecha_hora,
            motivo=c.motivo,
            estado=c.estado,
            diagnostico=c.diagnostico,
            tratamiento=c.tratamiento,
            plan_nutricional=c.plan_nutricional
        ))
    return resultado

@app.post("/citas", response_model=CitaOut, tags=["Citas"])
def agendar_cita(
    cita: CitaCreate,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(get_current_user)
):
    paciente = db.query(PacienteDB).filter(PacienteDB.id == cita.paciente_id).first()
    if not paciente:
        raise HTTPException(status_code=404, detail="El paciente no existe")
    
    profesional = db.query(UsuarioDB).filter(UsuarioDB.id == cita.profesional_id).first()
    if not profesional:
        raise HTTPException(status_code=404, detail="El profesional no existe")

    nueva_cita = CitaDB(**cita.model_dump())
    db.add(nueva_cita)
    db.commit()
    db.refresh(nueva_cita)

    return CitaOut(
        id=nueva_cita.id,
        paciente_id=nueva_cita.paciente_id,
        profesional_id=nueva_cita.profesional_id,
        nombre_paciente=paciente.nombre,
        nombre_profesional=profesional.username,
        rol_profesional=profesional.rol.value,
        fecha_hora=nueva_cita.fecha_hora,
        motivo=nueva_cita.motivo,
        estado=nueva_cita.estado,
        diagnostico=nueva_cita.diagnostico,
        tratamiento=nueva_cita.tratamiento,
        plan_nutricional=nueva_cita.plan_nutricional
    )

@app.post("/citas/{cita_id}/atencion-medica", response_model=CitaOut, tags=["Citas"])
def registrar_atencion_medica(
    cita_id: int,
    atencion: AtencionMedica,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(verificar_roles([RolUsuario.MEDICO]))
):
    cita = db.query(CitaDB).filter(CitaDB.id == cita_id).first()
    if not cita:
        raise HTTPException(status_code=404, detail="Cita no encontrada")

    cita.diagnostico = atencion.diagnostico
    cita.tratamiento = atencion.tratamiento
    cita.estado = EstadoCita.COMPLETADA
    db.commit()
    db.refresh(cita)

    return CitaOut(
        id=cita.id,
        paciente_id=cita.paciente_id,
        profesional_id=cita.profesional_id,
        nombre_paciente=cita.paciente.nombre,
        nombre_profesional=cita.profesional.username,
        rol_profesional=cita.profesional.rol.value,
        fecha_hora=cita.fecha_hora,
        motivo=cita.motivo,
        estado=cita.estado,
        diagnostico=cita.diagnostico,
        tratamiento=cita.tratamiento,
        plan_nutricional=cita.plan_nutricional
    )

@app.post("/citas/{cita_id}/atencion-nutricional", response_model=CitaOut, tags=["Citas"])
def registrar_atencion_nutricional(
    cita_id: int,
    atencion: AtencionNutricional,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(verificar_roles([RolUsuario.NUTRICIONISTA]))
):
    cita = db.query(CitaDB).filter(CitaDB.id == cita_id).first()
    if not cita:
        raise HTTPException(status_code=404, detail="Cita no encontrada")

    cita.plan_nutricional = atencion.plan_nutricional
    cita.estado = EstadoCita.COMPLETADA
    db.commit()
    db.refresh(cita)

    return CitaOut(
        id=cita.id,
        paciente_id=cita.paciente_id,
        profesional_id=cita.profesional_id,
        nombre_paciente=cita.paciente.nombre,
        nombre_profesional=cita.profesional.username,
        rol_profesional=cita.profesional.rol.value,
        fecha_hora=cita.fecha_hora,
        motivo=cita.motivo,
        estado=cita.estado,
        diagnostico=cita.diagnostico,
        tratamiento=cita.tratamiento,
        plan_nutricional=cita.plan_nutricional
    )

# --- REPORTES Y ADMIN ---
@app.get("/reportes/resumen", tags=["Reportes"])
def obtener_reporte_resumen(
    db: Session = Depends(get_db),
    current_user: UsuarioDB = Depends(get_current_user)
):
    total_pacientes = db.query(PacienteDB).count()
    
    if current_user.rol == RolUsuario.ADMIN:
        query_citas = db.query(CitaDB)
        total_usuarios = db.query(UsuarioDB).count()
    else:
        query_citas = db.query(CitaDB).filter(CitaDB.profesional_id == current_user.id)
        total_usuarios = 1

    return {
        "rol_actual": current_user.rol,
        "total_pacientes": total_pacientes,
        "total_citas": query_citas.count(),
        "citas_programadas": query_citas.filter(CitaDB.estado == EstadoCita.PROGRAMADA).count(),
        "citas_completadas": query_citas.filter(CitaDB.estado == EstadoCita.COMPLETADA).count(),
        "citas_canceladas": query_citas.filter(CitaDB.estado == EstadoCita.CANCELADA).count(),
        "total_usuarios": total_usuarios
    }

@app.post("/admin/usuarios", response_model=UsuarioOut, tags=["Administración"])
def registrar_usuario(
    usuario: UsuarioCreate, 
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(verificar_roles([RolUsuario.ADMIN]))
):
    if db.query(UsuarioDB).filter(UsuarioDB.username == usuario.username).first():
        raise HTTPException(status_code=400, detail="Nombre de usuario ya existente")
    
    nuevo_usuario = UsuarioDB(
        username=usuario.username,
        email=usuario.email,
        hashed_password=hash_password(usuario.password),
        rol=usuario.rol
    )
    db.add(nuevo_usuario)
    db.commit()
    db.refresh(nuevo_usuario)
    return nuevo_usuario