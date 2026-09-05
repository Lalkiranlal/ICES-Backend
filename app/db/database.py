import logging
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from app.core.config import settings

logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

# Configure connection args based on database dialect
db_url = settings.DATABASE_URL
connect_args = {}
if "sqlite" in db_url:
    connect_args["check_same_thread"] = False

engine_kwargs = {
    "echo": False,
    "future": True,
    "connect_args": connect_args,
}

if "postgresql" in db_url:
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_recycle"] = 300

engine = create_async_engine(db_url, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def init_db():
    """
    Initializes the database by registering and creating all tables.
    Works automatically with SQLite and PostgreSQL without needing complex migration steps.
    """
    try:
        # Import models so Base has metadata registered
        from app.db import models  # noqa: F401
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info(f"Database initialized successfully ({'SQLite' if 'sqlite' in db_url else 'PostgreSQL'}).")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")

async def get_db():
    """Dependency for obtaining an async session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
