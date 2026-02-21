import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.orm import sessionmaker

sqlite_file_name = "domyntrix.db"
sqlite_url = os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///./{sqlite_file_name}")

engine = create_async_engine(sqlite_url, echo=True)


async def get_session():
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session
