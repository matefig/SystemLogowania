from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.routers import auth
from app.database import engine, Base

Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="Bezpieczny System Logowania",
    description="Projekt z cyberbezpieczeństwa",
    version="1.0.0"
)

app.mount("/static", StaticFiles(directory="static"), name="static")


app.include_router(auth.router)

@app.get("/")
def read_root():
    # Zwraca plik HTML jako główną stronę
    return FileResponse("static/index.html")