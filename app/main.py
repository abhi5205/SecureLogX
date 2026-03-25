from app.security import create_access_token, verify_password, hash_password, SECRET_KEY, ALGORITHM
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from app.database import engine, SessionLocal, get_db, get_user_by_username, create_log
from app.models import User, Log
from app.base import Base
from app import models
from app import schemas
from app.schemas import LogCreate, LogResponse


Base.metadata.create_all(bind=engine)

app = FastAPI()


def get_db():
    db = SessionLocal()
    try:    
        yield db
    finally:
        db.close()

@app.get("/")
def root():
    return {"message": "SecureLogX backend running"}


@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):

    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed = hash_password(user.password)

    db_user = models.User(
        username=user.username,
        password=hashed,
        role="user"
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {"message": "User created successfully"}


def create_security_log(db: Session, username: str, action: str):
    if "Failed" in action:
        log_level = "ERROR"
    else:
        log_level = "INFO"

    user = db.query(User).filter(User.username == username).first()

    new_log = Log(
        level=log_level,
        message=f"[AUTH] {username} - {action}",
        user_id=user.id if user else None
    )

    db.add(new_log)
    db.commit()

@app.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    db_user = get_user_by_username(db, form_data.username)

    if not db_user:
        create_security_log(db, form_data.username, "Failed login - invalid username")
        raise HTTPException(status_code=400, detail="Invalid username")
    

    if not verify_password(form_data.password, db_user.password):
        create_security_log(db, form_data.username, "Failed login - invalid password")
        raise HTTPException(status_code=400, detail="Invalid password")

    access_token = create_access_token(data={"sub": db_user.username})
    create_security_log(db, db_user.username, "Successful login")

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")

        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        db_user = get_user_by_username(db, username)

        if db_user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return db_user
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
@app.get("/dashboard")
def dashboard(current_user: User = Depends(get_current_user)):
    return {
        "message": "Dashboard working",
        "username": current_user.username,
        "role": current_user.role
    }

@app.get("/logs")
def get_logs(
    level: str = None,
    username: str = None,
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    query = db.query(Log)

    if level:
        query = query.filter(Log.level == level)

    if username:
        query = query.filter(Log.message.contains(username))

    logs = query.order_by(Log.timestamp.desc()).offset(skip).limit(limit).all()

    return logs 

def get_admin_user(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return current_user

@app.get("/admin")
def admin_panel(admin: User = Depends(get_admin_user)):
    return {
        "message": "Welcome Admin",
        "username": admin.username,
        "role": admin.role
    }

@app.post("/logs", response_model=LogResponse)
def create_log(
    log: LogCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    new_log = Log(
        level=log.level,
        message=log.message,
        user_id=current_user.id
    )   

    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    return new_log

@app.delete("/logs/{log_id}")
def delete_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    log = db.query(Log).filter(Log.id == log_id).first()

    if not log:
        raise HTTPException(status_code=404, detail="Log not found")

    db.delete(log)
    db.commit()

    return {"message": "Log deleted successfully"}

@app.get("/health")
def health():
    return {"status": "healthy"}