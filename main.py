import os
import csv
import io
from datetime import datetime, timedelta, timezone, date
import enum
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, ConfigDict
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Enum as SQLEnum, ForeignKey, Text, or_
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from sqlalchemy.pool import NullPool
from passlib.context import CryptContext
import jwt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ==============================================================================
# CONFIGURACIÓN DE BASE DE DATOS
# ==============================================================================

DATABASE_URL = os.getenv("POSTGRES_URL") or os.getenv("DATABASE_URL")

if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+pg8000://", 1)
    elif DATABASE_URL.startswith("postgresql://") and not DATABASE_URL.startswith("postgresql+pg8000://"):
        DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+pg8000://", 1)

    if "?" in DATABASE_URL:
        DATABASE_URL = DATABASE_URL.split("?")[0]

    engine = create_engine(
        DATABASE_URL,
        poolclass=NullPool,
        connect_args={"ssl_context": True}
    )
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

class TipoEmpleado(str, enum.Enum):
    ADMINISTRATIVO = "Administrativo"
    SUPERVISOR = "Supervisor Educativo"
    DOCENTE = "Docente"

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
    tipo_empleado = Column(SQLEnum(TipoEmpleado), nullable=True)
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

try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    print(f"Error inicializando tablas: {e}")

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

class UsuarioUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    rol: Optional[RolUsuario] = None

class UsuarioOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    rol: RolUsuario
    model_config = ConfigDict(from_attributes=True)

class PacienteCreate(BaseModel):
    nombre: str
    tipo_empleado: TipoEmpleado
    edad: int
    telefono: str
    antecedentes_medicos: Optional[str] = None

class PacienteUpdate(BaseModel):
    nombre: Optional[str] = None
    tipo_empleado: Optional[TipoEmpleado] = None
    edad: Optional[int] = None
    telefono: Optional[str] = None
    antecedentes_medicos: Optional[str] = None

class PacienteOut(BaseModel):
    id: int
    nombre: str
    tipo_empleado: Optional[TipoEmpleado] = None
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

class CitaUpdate(BaseModel):
    paciente_id: Optional[int] = None
    profesional_id: Optional[int] = None
    fecha_hora: Optional[datetime] = None
    motivo: Optional[str] = None
    estado: Optional[EstadoCita] = None

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
    try:
        db = SessionLocal()
        if not db.query(UsuarioDB).first():
            usuarios_iniciales = [
                UsuarioDB(username="Admin", email="admin@hospital.com", hashed_password=pwd_context.hash("Admin123"), rol=RolUsuario.ADMIN),
                UsuarioDB(username="Medico", email="perez@hospital.com", hashed_password=pwd_context.hash("Doc123"), rol=RolUsuario.MEDICO),
                UsuarioDB(username="Nutricionista", email="gomez@hospital.com", hashed_password=pwd_context.hash("Nutri123"), rol=RolUsuario.NUTRICIONISTA),
            ]
            db.add_all(usuarios_iniciales)
            db.commit()
        db.close()
    except Exception as e:
        print(f"Error en startup: {e}")

@app.get("/", tags=["General"])
def servir_frontend():
    index_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
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

@app.put("/pacientes/{paciente_id}", response_model=PacienteOut, tags=["Pacientes"])
def editar_paciente(
    paciente_id: int,
    datos: PacienteUpdate,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(verificar_roles([RolUsuario.ADMIN, RolUsuario.MEDICO]))
):
    paciente = db.query(PacienteDB).filter(PacienteDB.id == paciente_id).first()
    if not paciente:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")

    for key, value in datos.model_dump(exclude_unset=True).items():
        setattr(paciente, key, value)

    db.commit()
    db.refresh(paciente)
    return paciente

@app.delete("/pacientes/{paciente_id}", tags=["Pacientes"])
def eliminar_paciente(
    paciente_id: int,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(verificar_roles([RolUsuario.ADMIN, RolUsuario.MEDICO]))
):
    paciente = db.query(PacienteDB).filter(PacienteDB.id == paciente_id).first()
    if not paciente:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")

    db.query(CitaDB).filter(CitaDB.paciente_id == paciente_id).delete()
    db.delete(paciente)
    db.commit()
    return {"mensaje": "Paciente y sus citas eliminados correctamente"}

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
    buscar_paciente: Optional[str] = None,
    fecha: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: UsuarioDB = Depends(get_current_user)
):
    query = db.query(CitaDB).join(PacienteDB, CitaDB.paciente_id == PacienteDB.id)
    
    if current_user.rol in [RolUsuario.MEDICO, RolUsuario.NUTRICIONISTA]:
        query = query.filter(CitaDB.profesional_id == current_user.id)
        
    if buscar_paciente:
        query = query.filter(PacienteDB.nombre.ilike(f"%{buscar_paciente}%"))

    if fecha:
        try:
            fecha_dt = datetime.strptime(fecha, "%Y-%m-%d").date()
            query = query.filter(
                CitaDB.fecha_hora >= datetime.combine(fecha_dt, datetime.min.time()),
                CitaDB.fecha_hora <= datetime.combine(fecha_dt, datetime.max.time())
            )
        except ValueError:
            pass
        
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

@app.put("/citas/{cita_id}", response_model=CitaOut, tags=["Citas"])
def editar_cita(
    cita_id: int,
    datos: CitaUpdate,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(get_current_user)
):
    cita = db.query(CitaDB).filter(CitaDB.id == cita_id).first()
    if not cita:
        raise HTTPException(status_code=404, detail="Cita no encontrada")

    for key, value in datos.model_dump(exclude_unset=True).items():
        setattr(cita, key, value)

    db.commit()
    db.refresh(cita)

    return CitaOut(
        id=cita.id,
        paciente_id=cita.paciente_id,
        profesional_id=cita.profesional_id,
        nombre_paciente=cita.paciente.nombre if cita.paciente else "N/A",
        nombre_profesional=cita.profesional.username if cita.profesional else "N/A",
        rol_profesional=cita.profesional.rol.value if cita.profesional else "N/A",
        fecha_hora=cita.fecha_hora,
        motivo=cita.motivo,
        estado=cita.estado,
        diagnostico=cita.diagnostico,
        tratamiento=cita.tratamiento,
        plan_nutricional=cita.plan_nutricional
    )

@app.delete("/citas/{cita_id}", tags=["Citas"])
def eliminar_cita(
    cita_id: int,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(get_current_user)
):
    cita = db.query(CitaDB).filter(CitaDB.id == cita_id).first()
    if not cita:
        raise HTTPException(status_code=404, detail="Cita no encontrada")

    db.delete(cita)
    db.commit()
    return {"mensaje": "Cita eliminada correctamente"}

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

# --- ENDPOINTS DE EXPORTACIÓN A EXCEL (SOLO ADMIN) ---
@app.get("/admin/exportar/pacientes", tags=["Administración"])
def exportar_pacientes_excel(
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(verificar_roles([RolUsuario.ADMIN]))
):
    pacientes = db.query(PacienteDB).all()
    
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(["ID", "Nombre", "Tipo Empleado", "Edad", "Teléfono", "Antecedentes Médicos", "Fecha de Registro"])
    
    for p in pacientes:
        writer.writerow([
            p.id,
            p.nombre,
            p.tipo_empleado.value if p.tipo_empleado else "N/A",
            p.edad,
            p.telefono,
            (p.antecedentes_medicos or "").replace("\n", " "),
            p.fecha_registro.strftime("%Y-%m-%d %H:%M:%S") if p.fecha_registro else ""
        ])
    
    content = "\ufeff" + output.getvalue()
    return Response(
        content=content.encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=pacientes.csv"}
    )

@app.get("/admin/exportar/citas", tags=["Administración"])
def exportar_citas_excel(
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(verificar_roles([RolUsuario.ADMIN]))
):
    citas = db.query(CitaDB).all()
    
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(["ID Cita", "ID Paciente", "Paciente", "ID Profesional", "Profesional", "Rol Profesional", "Fecha y Hora", "Motivo", "Estado", "Diagnóstico", "Tratamiento", "Plan Nutricional"])
    
    for c in citas:
        writer.writerow([
            c.id,
            c.paciente_id,
            c.paciente.nombre if c.paciente else "N/A",
            c.profesional_id,
            c.profesional.username if c.profesional else "N/A",
            c.profesional.rol.value if c.profesional else "N/A",
            c.fecha_hora.strftime("%Y-%m-%d %H:%M:%S") if c.fecha_hora else "",
            c.motivo,
            c.estado.value if hasattr(c.estado, 'value') else c.estado,
            (c.diagnostico or "").replace("\n", " "),
            (c.tratamiento or "").replace("\n", " "),
            (c.plan_nutricional or "").replace("\n", " ")
        ])
    
    content = "\ufeff" + output.getvalue()
    return Response(
        content=content.encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=citas.csv"}
    )

@app.get("/admin/usuarios", response_model=List[UsuarioOut], tags=["Administración"])
def listar_usuarios(
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(verificar_roles([RolUsuario.ADMIN]))
):
    return db.query(UsuarioDB).all()

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

@app.put("/admin/usuarios/{usuario_id}", response_model=UsuarioOut, tags=["Administración"])
def editar_usuario(
    usuario_id: int,
    datos: UsuarioUpdate,
    db: Session = Depends(get_db),
    _: UsuarioDB = Depends(verificar_roles([RolUsuario.ADMIN]))
):
    usuario = db.query(UsuarioDB).filter(UsuarioDB.id == usuario_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if datos.username:
        existente = db.query(UsuarioDB).filter(UsuarioDB.username == datos.username, UsuarioDB.id != usuario_id).first()
        if existente:
            raise HTTPException(status_code=400, detail="El nombre de usuario ya esta en uso")
        usuario.username = datos.username

    if datos.email:
        existente_email = db.query(UsuarioDB).filter(UsuarioDB.email == datos.email, UsuarioDB.id != usuario_id).first()
        if existente_email:
            raise HTTPException(status_code=400, detail="El correo ya esta en uso")
        usuario.email = datos.email

    if datos.rol:
        usuario.rol = datos.rol

    if datos.password:
        usuario.hashed_password = hash_password(datos.password)

    db.commit()
    db.refresh(usuario)
    return usuario

@app.delete("/admin/usuarios/{usuario_id}", tags=["Administración"])
def eliminar_usuario(
    usuario_id: int,
    db: Session = Depends(get_db),
    current_user: UsuarioDB = Depends(verificar_roles([RolUsuario.ADMIN]))
):
    if current_user.id == usuario_id:
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propio usuario activo")

    usuario = db.query(UsuarioDB).filter(UsuarioDB.id == usuario_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db.query(CitaDB).filter(CitaDB.profesional_id == usuario_id).delete()
    db.delete(usuario)
    db.commit()
    return {"mensaje": "Usuario y sus citas asociadas eliminados correctamente"}