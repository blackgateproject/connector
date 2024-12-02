from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field
from sqlmodel import Field, SQLModel


class Token(BaseModel):
    access_token: str
    token_type: str
