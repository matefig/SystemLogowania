from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import pyotp


# Importujemy nasze moduły
from app import models, schemas, security, password_policy
from app.database import get_db

router = APIRouter(prefix="/auth", tags=["Autentykacja"])

# Stałe do polityki blokowania konta
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 15


@router.post("/register", response_model=schemas.UserResponse)
async def register_user(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    """Rejestracja nowego użytkownika z rygorystycznym sprawdzaniem hasła."""

    # 1. Sprawdzenie, czy e-mail nie jest już zajęty
    existing_user = db.query(models.User).filter(models.User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Użytkownik o tym adresie e-mail już istnieje."
        )

    # 2. Walidacja polityki haseł (Długość, Entropia, API HaveIBeenPwned)
    is_valid, error_message = await password_policy.validate_password_policy(user_data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    # 3. Haszowanie hasła (Argon2 automatycznie generuje i dodaje bezpieczną sól)
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
    """Bezpieczne logowanie z ochroną Brute-Force i weryfikacją TOTP."""

    user = db.query(models.User).filter(models.User.email == user_data.email).first()

    # 1. Zabezpieczenie przed wyliczaniem użytkowników (User Enumeration)
    # Zawsze zwracamy ten sam, ogólny komunikat błędu.
    invalid_credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Nieprawidłowy e-mail lub hasło."
    )

    if not user:
        raise invalid_credentials_exception

    # 2. Sprawdzenie blokady konta (Rate limiting / Lockout)
    if user.locked_until and user.locked_until > datetime.now():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Konto zostało tymczasowo zablokowane z powodu zbyt wielu nieudanych prób logowania. Spróbuj ponownie później."
        )

    # 3. Weryfikacja hasła (Argon2)
    if not security.verify_password(user_data.password, user.hashed_password):
        # Inkrementacja licznika błędów
        user.failed_login_attempts += 1

        # Jeśli przekroczono limit, blokujemy konto
        if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)

        db.commit()
        raise invalid_credentials_exception

    # 4. Sprawdzenie uwierzytelnienia dwuskładnikowego (TOTP)
    if user.is_totp_enabled:
        if not user_data.totp_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Wymagany jest kod 2FA (TOTP)."
            )

        # Generowanie obiektu TOTP na podstawie sekretu użytkownika z bazy
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(user_data.totp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Nieprawidłowy kod 2FA."
            )

    # 5. Udane logowanie: resetowanie liczników błędów!
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    # 6. Zwrócenie tokenu sesji
    # Na potrzeby samego systemu logowania zwracamy tu prosty identyfikator.
    # W pełnej aplikacji należałoby w tym miejscu wygenerować token JWT.
    return {
        "access_token": f"sesja_uzytkownika_{user.id}",
        "token_type": "bearer"
    }
