from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import pyotp
import urllib.parse


from app import models, schemas, security, password_policy
from app.database import get_db

router = APIRouter(prefix="/auth", tags=["Autentykacja"])


MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 15


@router.post("/register", response_model=schemas.UserResponse)
async def register_user(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    """Rejestracja nowego użytkownika"""

    # 1. Sprawdzenie, czy e-mail nie jest już zajęty
    existing_user = db.query(models.User).filter(models.User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Użytkownik o tym adresie e-mail już istnieje."
        )

    # 2. Walidacja polityki haseł
    is_valid, error_message = await password_policy.validate_password_policy(user_data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    # 3. Haszowanie hasła
    hashed_password = security.get_password_hash(user_data.password)

    # 4. Zapis do bazy danych
    new_user = models.User(
        email=user_data.email,
        hashed_password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login", response_model=schemas.Token)
def login_user(user_data: schemas.UserLogin, db: Session = Depends(get_db)):
    """Logowanie"""

    user = db.query(models.User).filter(models.User.email == user_data.email).first()

    invalid_credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Nieprawidłowy e-mail lub hasło."
    )

    if not user:
        raise invalid_credentials_exception

    # 2. Sprawdzenie blokady
    if user.locked_until and user.locked_until > datetime.now():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Konto zostało tymczasowo zablokowane z powodu zbyt wielu nieudanych prób logowania. Spróbuj ponownie później."
        )

    # 3. Weryfikacja hasła
    if not security.verify_password(user_data.password, user.hashed_password):
        # Inkrementacja licznika błędów
        user.failed_login_attempts += 1

        # Jeśli przekroczono limit, blokujemy konto
        if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)

        db.commit()
        raise invalid_credentials_exception

    # 4. Sprawdzenie uwierzytelnienia
    if user.is_totp_enabled:
        if not user_data.totp_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Wymagany jest kod 2FA (TOTP)."
            )

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(user_data.totp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Nieprawidłowy kod 2FA."
            )

    # 5. Udane logowanie:
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    # 6. Zwrócenie tokenu sesji
    return {
        "access_token": f"sesja_uzytkownika_{user.id}",
        "token_type": "bearer",
        "email": user.email
    }


@router.post("/setup-2fa", response_model=schemas.TwoFactorSetupResponse)
def setup_2fa(email: str = Body(embed=True), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Użytkownik nie istnieje.")

    secret = pyotp.random_base32()
    user.totp_secret = secret
    user.is_totp_enabled = True
    db.commit()

    totp_uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="SecureGames")
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={urllib.parse.quote(totp_uri)}"

    return {
        "message": "2FA zostało włączone!",
        "secret": secret,
        "instrukcja": "Zeskanuj poniższy QR kod w aplikacji",
        "qr_code_url": qr_url
    }