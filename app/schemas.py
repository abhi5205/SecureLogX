from pydantic import BaseModel
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str
    
class LogCreate(BaseModel):
    level: str
    message: str

class LogResponse(BaseModel):
    id: int
    level: str
    message: str
    timestamp: datetime

    class Config:
        orm_mode = True