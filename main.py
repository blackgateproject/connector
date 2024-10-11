"""
- BC atm just stores the DID and serves VC upon successful DID Issues
- Forward PII sent from dashboard to the BC
    - Use a very basic DB to store PII hashes that were used to generate the DID
- Forward VC requests to the BC

"""

from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Field, Session, SQLModel, create_engine, select
from starlette.responses import RedirectResponse, JSONResponse

BLOCKCHAIN_URL = "http://localhost:8545"
DASHBOARD_URL = "http://localhost:5713"

DATABASE_URL = "sqlite:///./mainDatabase.db"

# Setup DB On Server Start
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Create DB Tables
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

# Connect to the DB
SessionDep = Annotated[Session, Depends(lambda: Session(engine))]

class User(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    fName: str
    lName: str
    email: str
    phone: str
    address: str
    vc: str
    role: str

# Startup Backend
app = FastAPI()

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

################################################################
###################### Dashboard Routes ########################
################################################################


################################################################
##################### Blockchain Routes ########################
################################################################
