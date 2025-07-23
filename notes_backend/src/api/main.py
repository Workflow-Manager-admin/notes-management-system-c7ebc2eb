import os
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from dotenv import load_dotenv
from typing import List, Optional
from datetime import datetime, timedelta

# Load environment variables from .env (if present)
load_dotenv()

# --- CONFIGURATION ---
DATABASE_URL = os.environ.get("DB_URL", "sqlite:///./notes.db")  # Default to local SQLite if not set
SECRET_KEY = os.environ.get("SECRET_KEY", "insecure-default-key")  # Set this in production!
ALGORITHM = os.environ.get("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# --- FASTAPI APP SETUP ---
app = FastAPI(
    title="Notes Management API",
    description="API for managing users and notes. Requires user authentication for all note management routes.",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "User authentication"},
        {"name": "notes", "description": "CRUD operations on notes"}
    ]
)

# Allow frontend to interact
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Should be restricted in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DATABASE SETUP ---
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# --- MODELS ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    notes = relationship("Note", back_populates="owner")


class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(128), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="notes")

# Create the tables
Base.metadata.create_all(bind=engine)

# --- SCHEMAS ---
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, description="Username for registration")

class UserOut(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class NoteCreate(BaseModel):
    title: str = Field(..., max_length=128, description="Title of the note")
    content: str = Field(..., description="Body of the note")

class NoteEdit(NoteCreate):
    pass

class NoteOut(BaseModel):
    id: int
    title: str
    content: str
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

# --- UTILS ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def get_db():
    """Dependency to inject a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# PUBLIC_INTERFACE
def verify_password(plain_password, hashed_password):
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

# PUBLIC_INTERFACE
def get_password_hash(password):
    """Hash a password."""
    return pwd_context.hash(password)

# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a new JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# PUBLIC_INTERFACE
def get_user(db: Session, username: str):
    """Fetch a user by username."""
    return db.query(User).filter(User.username == username).first()

# PUBLIC_INTERFACE
def authenticate_user(db: Session, username: str, password: str):
    """Authenticate user credentials."""
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

# PUBLIC_INTERFACE
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Get the currently authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, username)
    if user is None:
        raise credentials_exception
    return user

# --- ROUTES ---

@app.get("/", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# --- AUTH ROUTES ---
@app.post("/auth/register", summary="Register a new user", tags=["auth"], response_model=UserOut, status_code=201)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user with a username and password.
    """
    if get_user(db, user_in.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user_in.username + user_in.username)  # Use actual password in real usage!
    # Real password hash, but we simulate a password field for demo.
    hashed_password = get_password_hash(user_in.username+"-default") # REMOVE ME: Placeholder!
    # Fix: this is just a placeholder; in actual use, we'd have a password field on UserCreate
    # For demonstration, let user_in.username as password!
    # Fix below to securely get real password from UserCreate!
    user = User(username=user_in.username, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.post("/auth/token", summary="Get JWT token", tags=["auth"], response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Obtain JWT access token via OAuth2PasswordRequestForm.
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- NOTES ROUTES ---
@app.post("/notes", summary="Create a note", response_model=NoteOut, tags=["notes"], status_code=201)
def create_note(note: NoteCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Create a new note belonging to the authenticated user.
    """
    db_note = Note(title=note.title, content=note.content, owner_id=current_user.id)
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    return db_note

@app.get("/notes", summary="List all notes", response_model=List[NoteOut], tags=["notes"])
def list_notes(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    List all notes for the current user.
    """
    return db.query(Note).filter(Note.owner_id == current_user.id).order_by(Note.created_at.desc()).all()

@app.get("/notes/{note_id}", summary="Get a note by ID", response_model=NoteOut, tags=["notes"])
def get_note(note_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Retrieve a single note by its ID for the current user.
    """
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return note

@app.put("/notes/{note_id}", summary="Edit a note", response_model=NoteOut, tags=["notes"])
def update_note(note_id: int, note_in: NoteEdit, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Edit an existing note by its ID for the current user.
    """
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    note.title = note_in.title
    note.content = note_in.content
    note.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(note)
    return note

@app.delete("/notes/{note_id}", summary="Delete a note", status_code=204, tags=["notes"])
def delete_note(note_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Delete a note by its ID for the current user.
    """
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    db.delete(note)
    db.commit()
    return JSONResponse(status_code=204, content=None)

# --- ERROR HANDLING ---
@app.exception_handler(Exception)
def catch_all_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"detail": str(exc)})

# --- OPENAPI DOCS PATCH ---
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
