import re
from typing import Annotated

from pydantic import BaseModel, EmailStr, Field, field_validator


class UserLogin(BaseModel):
    username: Annotated[str, Field(min_length=3, max_length=50)]
    password: Annotated[str, Field(min_length=1, max_length=128)]


class UserCreate(BaseModel):
    username: Annotated[
        str, Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    ]
    email: EmailStr
    password: Annotated[str, Field(min_length=8, max_length=128)]

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserOut(BaseModel):
    id: Annotated[int, Field(gt=0)]
    username: Annotated[str, Field(min_length=3, max_length=50)]
    email: EmailStr
    is_active: bool
    is_admin: bool

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: Annotated[str, Field(min_length=1)]
    token_type: Annotated[str, Field(pattern=r"^Bearer$")] = "Bearer"


class TokenData(BaseModel):
    username: Annotated[str, Field(min_length=3, max_length=50)] | None = None
