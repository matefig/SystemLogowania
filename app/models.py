from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

    # TOTP (2FA)
    totp_secret = Column(String, nullable=True)
    is_totp_enabled = Column(Boolean, default=False)

    # Blokada konta (Brute-force protection)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)