from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
from models import Base, User

# Database URL
# Prioritize DATABASE_URL from environment, otherwise fallback to SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/ti_watchlist.db")

print(f"--- Using database: {DATABASE_URL} ---")

# Create engine
# For PostgreSQL, we don't need check_same_thread
if DATABASE_URL.startswith("postgresql"):
    engine = create_engine(DATABASE_URL)
else:
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Create all tables
def init_db():
    # Create data directory if it doesn't exist
    if DATABASE_URL.startswith("sqlite"):
        os.makedirs("./data", exist_ok=True)
    
    # Try to use Alembic migrations, fallback to create_all if migrations don't exist
    try:
        from alembic.config import Config
        from alembic import command
        
        alembic_cfg = Config("alembic.ini")
        # Run migrations to head
        command.upgrade(alembic_cfg, "head")
    except Exception as e:
        # If migrations fail (e.g., no migrations exist yet), fallback to create_all
        # This allows the app to work even if migrations haven't been initialized
        print(f"Warning: Could not run migrations: {e}. Using create_all() as fallback.")
        Base.metadata.create_all(bind=engine)

    # Create default user if it doesn't exist
    db = SessionLocal()
    user = db.query(User).first()
    if not user:
        user = User(
            username="analyst",
            hashed_password="password"
        )
        db.add(user)
        db.commit()
    db.close()


# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()