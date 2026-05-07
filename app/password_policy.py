import math
import hashlib
import httpx
import re

# Stałe określające wielkość puli znaków
POOL_LOWERCASE = 26
POOL_UPPERCASE = 26
POOL_DIGITS = 10
POOL_SPECIAL = 32


def calculate_entropy(password: str) -> float:
    """Oblicza entropię matematyczną hasła w bitach."""
    if not password:
        return 0.0

    pool_size = 0
    if re.search(r'[a-z]', password):
        pool_size += POOL_LOWERCASE
    if re.search(r'[A-Z]', password):
        pool_size += POOL_UPPERCASE
    if re.search(r'[0-9]', password):
        pool_size += POOL_DIGITS
    if re.search(r'[^a-zA-Z0-9]', password):
        pool_size += POOL_SPECIAL

    if pool_size == 0:
        return 0.0

    # E = L * log2(R)
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


async def check_pwned_passwords(password: str) -> bool:
    """
    Sprawdza, czy hasło wyciekło, używając API HaveIBeenPwned.
    Zgodnie z dobrymi praktykami wysyłamy tylko 5 pierwszych znaków skrótu SHA-1 (K-Anonymity).
    Zwraca True, jeśli hasło zostało skompromitowane.
    """
    # API wymaga skrótu SHA-1 (wielkimi literami)
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    # Wykonujemy zapytanie asynchronicznie, by nie blokować aplikacji
    async with httpx.AsyncClient() as client:
        response = await client.get(url)

    if response.status_code != 200:
        # W razie awarii API przepuszczamy hasło (Fail Open)
        return False

    # Sprawdzamy, czy reszta naszego hasha znajduje się w odpowiedzi
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return True  # Hasło wyciekło!

    return False


async def validate_password_policy(password: str) -> tuple[bool, str]:
    """
    Waliduje hasło na podstawie OWASP ASVS i entropii.
    Zwraca krotkę: (Czy_poprawne, Komunikat_błędu)
    """
    if len(password) < 12:
        return False, "Hasło musi mieć co najmniej 12 znaków (OWASP)."

    entropy = calculate_entropy(password)
    # Przyjmujemy minimum 50 bitów entropii jako rozsądny standard
    if entropy < 50:
        return False, f"Zbyt słabe hasło (Entropia: {entropy} bitów). Użyj bardziej różnorodnych znaków."

    is_pwned = await check_pwned_passwords(password)
    if is_pwned:
        return False, "To hasło pojawiło się w wyciekach danych. Wybierz inne."

    return True, "Hasło jest silne i bezpieczne."