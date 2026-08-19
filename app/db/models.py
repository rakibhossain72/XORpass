import os
import base64
import uuid
from sqlalchemy import Column, String, Text, ForeignKey, TypeDecorator
from sqlalchemy.orm import relationship
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from app.db.database import Base

# DB Encryption Key derivation
DB_SECRET = os.environ.get("DB_ENCRYPTION_SECRET", "default-db-storage-key-xorpass-2026").encode('utf-8')
salt = b'xorpass_db_salt_static'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
db_fernet_key = base64.urlsafe_b64encode(kdf.derive(DB_SECRET))
cipher_suite = Fernet(db_fernet_key)

class EncryptedString(TypeDecorator):
    """
    SQLAlchemy TypeDecorator that encrypts text when writing to the SQLite database
    and decrypts text when reading from the SQLite database.
    """
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, str):
            value_bytes = value.encode('utf-8')
        else:
            value_bytes = value
        encrypted = cipher_suite.encrypt(value_bytes)
        return encrypted.decode('utf-8')

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            decrypted = cipher_suite.decrypt(value.encode('utf-8'))
            return decrypted.decode('utf-8')
        except Exception:
            return value

class User(Base):
    __tablename__ = "users"

    email = Column(String, primary_key=True, index=True)
    password = Column(EncryptedString, nullable=False)
    public_key = Column(EncryptedString, nullable=False)
    private_key = Column(EncryptedString, nullable=False)

    passwords = relationship("PasswordEntry", back_populates="owner", cascade="all, delete-orphan")

class PasswordEntry(Base):
    __tablename__ = "passwords"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    website = Column(EncryptedString, nullable=False)
    email = Column(EncryptedString, nullable=False)
    password = Column(EncryptedString, nullable=False)
    owner_id = Column(String, ForeignKey("users.email"), nullable=False, index=True)
    difficulty = Column(String, nullable=False)

    owner = relationship("User", back_populates="passwords")
