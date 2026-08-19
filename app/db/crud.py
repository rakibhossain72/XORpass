from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update, delete
from app.db.models import User, PasswordEntry

async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).filter(User.email == email))
    return result.scalars().first()

async def create_user(db: AsyncSession, email: str, password_hash: str, public_key: str, private_key: str) -> User:
    user = User(
        email=email,
        password=password_hash,
        public_key=public_key,
        private_key=private_key
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user

async def update_user(db: AsyncSession, email: str, data: dict):
    stmt = update(User).where(User.email == email).values(**data)
    await db.execute(stmt)
    await db.commit()

async def delete_user(db: AsyncSession, email: str):
    stmt = delete(User).where(User.email == email)
    await db.execute(stmt)
    await db.commit()

async def add_password_entry(db: AsyncSession, website: str, email: str, password: str, owner_id: str, difficulty: str) -> PasswordEntry:
    entry = PasswordEntry(
        website=website,
        email=email,
        password=password,
        owner_id=owner_id,
        difficulty=difficulty
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry

async def get_password_entries_by_owner(db: AsyncSession, owner_id: str):
    result = await db.execute(select(PasswordEntry).filter(PasswordEntry.owner_id == owner_id))
    return result.scalars().all()

async def get_password_entry_by_id(db: AsyncSession, entry_id: str) -> PasswordEntry | None:
    result = await db.execute(select(PasswordEntry).filter(PasswordEntry.id == entry_id))
    return result.scalars().first()

async def update_password_entry(db: AsyncSession, entry_id: str, data: dict):
    stmt = update(PasswordEntry).where(PasswordEntry.id == entry_id).values(**data)
    await db.execute(stmt)
    await db.commit()

async def delete_password_entry(db: AsyncSession, entry_id: str):
    stmt = delete(PasswordEntry).where(PasswordEntry.id == entry_id)
    await db.execute(stmt)
    await db.commit()
