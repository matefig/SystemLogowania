from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Importujemy nasz router autentykacji oraz bazę danych
from app.routers import auth
from app.database import engine, Base

# Tworzymy tabele w bazie danych (jeśli jeszcze nie istnieją)
Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="Bezpieczny System Logowania API",
    description="Projekt z cyberbezpieczeństwa (Argon2, Entropia, 2FA, Lockout, Pwned Passwords)",
    version="1.0.0"
)

app.mount("/static", StaticFiles(directory="static"), name="static")

# Konfiguracja CORS (Cross-Origin Resource Sharing)
# Pozwala to na ewentualne podłączenie frontendu (np. w React lub Vue) w przyszłości
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # W produkcji zmienilibyśmy to na konkretną domenę!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Podpinamy nasz router z pliku app/routers/auth.py
app.include_router(auth.router)

# Prosty endpoint powitalny
@app.get("/")
def read_root():
    # Zwraca plik HTML jako główną stronę
    return FileResponse("static/index.html")