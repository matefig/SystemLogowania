from passlib.context import CryptContext

# Konfiguracja Passlib do używania algorytmu Argon2
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Sprawdza, czy podane hasło pasuje do hasha w bazie."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Generuje skrót Argon2.
    Passlib automatycznie generuje bezpieczną, unikalną sól dla każdego hasła
    i dołącza ją do wyniku.
    """
    return pwd_context.hash(password)