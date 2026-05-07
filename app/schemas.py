from pydantic import BaseModel, EmailStr
from typing import Optional

# 1. Schemat do REJESTRACJI
class UserCreate(BaseModel):
    email: EmailStr  # Automatycznie sprawdzi, czy to poprawny adres e-mail
    password: str

# 2. Schemat do LOGOWANIA
class UserLogin(BaseModel):
    email: EmailStr
    password: str
    totp_code: Optional[str] = None  # Kod z Google Authenticator (opcjonalny, bo nie każdy go włączy)

# 3. Schemat ZWRACANY do użytkownika (zauważ: BRAK HASŁA!)
class UserResponse(BaseModel):
    id: int
    email: EmailStr
    is_totp_enabled: bool

    class Config:
        from_attributes = True  # Pozwala Pydanticowi czytać z modeli SQLAlchemy

# 4. Schemat TOKENA (który użytkownik dostaje po udanym logowaniu)
class Token(BaseModel):
    access_token: str
    token_type: str