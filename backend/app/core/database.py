from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.core.config import settings

engine = create_engine(
	settings.database_url,
	pool_pre_ping=True,
	pool_recycle=300,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, class_=Session)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
	session = SessionLocal()
	try:
		yield session
	finally:
		session.close()
