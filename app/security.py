from passlib.context import CryptContext

# Konfiguracja Passlib do używania algorytmu Argon2
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__time_cost=1,
    argon2__memory_cost=8192,
    argon2__parallelism=1
)

def verify_password(plain_password: str, hashed_password: str) -> bool:

    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:

    return pwd_context.hash(password)