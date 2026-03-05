from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc
from sqlalchemy.exc import SQLAlchemyError
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
import os
import requests

from database import get_db, init_db
from models import (
    User, Board, Pin, Snapshot, Alert,
    BoardCreate, BoardResponse,
    PinCreate, PinResponse,
    SnapshotCreate, SnapshotResponse,
    AlertCreate, AlertResponse
)

app = FastAPI(title="TI Analyst's Watchlist API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for local development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Get or create default user (single user system)
def get_default_user(db: Session):
    try:
        user = db.query(User).first()
        if not user:
            # Create default user
            user = User(
                username="analyst",
                hashed_password="password"  # Not used, but required by schema
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        return user
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")


# ============ BOARDS ENDPOINTS (No Auth) ============

@app.get("/api/boards", response_model=List[BoardResponse])
async def get_boards(db: Session = Depends(get_db)):
    try:
        user = get_default_user(db)
        boards = db.query(Board).filter(Board.user_id == user.id).all()
        return boards
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching boards: {str(e)}")


@app.post("/api/boards", response_model=BoardResponse)
async def create_board(board: BoardCreate, db: Session = Depends(get_db)):
    try:
        user = get_default_user(db)
        db_board = Board(user_id=user.id, name=board.name)
        db.add(db_board)
        db.commit()
        db.refresh(db_board)
        return db_board
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating board: {str(e)}")


@app.delete("/api/boards/{board_id}")
async def delete_board(board_id: int, db: Session = Depends(get_db)):
    try:
        user = get_default_user(db)
        board = db.query(Board).filter(
            Board.id == board_id, Board.user_id == user.id
        ).first()
        if not board:
            raise HTTPException(status_code=404, detail="Board not found")
        
        db.delete(board)
        db.commit()
        return {"message": "Board deleted"}
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting board: {str(e)}")


# ============ PINS ENDPOINTS (No Auth) ============

@app.post("/api/pins", response_model=PinResponse)
async def create_pin(pin: PinCreate, db: Session = Depends(get_db)):
    try:
        user = get_default_user(db)
        # Verify board belongs to default user
        board = db.query(Board).filter(Board.id == pin.board_id, Board.user_id == user.id).first()
        if not board:
            raise HTTPException(status_code=404, detail="Board not found")
        
        db_pin = Pin(board_id=pin.board_id, ioc_value=pin.ioc_value, ioc_type=pin.ioc_type)
        db.add(db_pin)
        db.commit()
        db.refresh(db_pin)
        
        return db_pin
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating pin: {str(e)}")


@app.delete("/api/pins/{pin_id}")
async def delete_pin(pin_id: int, db: Session = Depends(get_db)):
    try:
        user = get_default_user(db)
        pin = db.query(Pin).join(Board).filter(
            Pin.id == pin_id, Board.user_id == user.id
        ).first()
        if not pin:
            raise HTTPException(status_code=404, detail="Pin not found")
        
        db.delete(pin)
        db.commit()
        return {"message": "Pin deleted"}
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting pin: {str(e)}")


# ============ ALERTS ENDPOINTS (No Auth) ============

@app.get("/api/alerts", response_model=List[AlertResponse])
async def get_alerts(db: Session = Depends(get_db)):
    try:
        user = get_default_user(db)
        alerts = db.query(Alert).join(Pin).join(Board).filter(
            Board.user_id == user.id
        ).order_by(desc(Alert.timestamp)).all()
        return alerts
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching alerts: {str(e)}")



# ============ INTERNAL ENDPOINTS ============

@app.get("/api/internal/pins-to-check")
async def get_pins_to_check(db: Session = Depends(get_db)):
    pins = db.query(Pin).filter(Pin.active == True).all()
    return [{"id": p.id, "board_id": p.board_id, "ioc_value": p.ioc_value, 
             "ioc_type": p.ioc_type, "active": p.active} for p in pins]


@app.get("/api/internal/baseline/{pin_id}")
async def get_baseline(pin_id: int, db: Session = Depends(get_db)):
    snapshot = db.query(Snapshot).filter(Snapshot.pin_id == pin_id).order_by(
        desc(Snapshot.timestamp)
    ).first()
    
    if not snapshot:
        return {"pin_id": pin_id, "full_report_json": {}}
    
    return {
        "id": snapshot.id,
        "pin_id": snapshot.pin_id,
        "timestamp": snapshot.timestamp,
        "full_report_json": snapshot.full_report_json
    }


@app.post("/api/internal/snapshot", response_model=SnapshotResponse)
async def create_snapshot(snapshot: SnapshotCreate, db: Session = Depends(get_db)):
    try:
        db_snapshot = Snapshot(
            pin_id=snapshot.pin_id,
            full_report_json=snapshot.full_report_json
        )
        db.add(db_snapshot)
        db.commit()
        db.refresh(db_snapshot)
        return db_snapshot
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating snapshot: {str(e)}")


@app.post("/api/internal/alert", response_model=AlertResponse)
async def create_alert(alert: AlertCreate, db: Session = Depends(get_db)):
    try:
        db_alert = Alert(
            pin_id=alert.pin_id,
            delta_data=alert.delta_data
        )
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)
        return db_alert
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating alert: {str(e)}")


# ============ API STATUS ENDPOINT ============

def _test_virustotal_api() -> Dict[str, Any]:
    """Test VirusTotal API connection"""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"connected": False, "message": "Missing VIRUSTOTAL_API_KEY in environment"}
    
    try:
        url = "https://www.virustotal.com/api/v3/users/me"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return {"connected": True, "message": "Successfully connected"}
        elif response.status_code == 401:
            return {"connected": False, "message": "Unauthorized: Invalid API Key"}
        else:
            return {"connected": False, "message": f"API Error: HTTP {response.status_code}"}
    except requests.exceptions.Timeout:
        return {"connected": False, "message": "Connection timeout"}
    except requests.exceptions.RequestException as e:
        return {"connected": False, "message": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"connected": False, "message": f"Unexpected error: {str(e)}"}


def _test_malwarebazaar_api() -> Dict[str, Any]:
    """Test MalwareBazaar API connection"""
    api_key = os.getenv("MALWAREBAZAAR_API_KEY")
    
    try:
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {"query": "get_recent", "selector": "time"}
        headers = {}
        if api_key:
            headers["Auth-Key"] = api_key
        
        response = requests.post(url, data=data, headers=headers, timeout=10)
        
        if response.status_code in [200, 400]:
            return {"connected": True, "message": "Successfully connected"}
        elif response.status_code == 401:
            return {"connected": False, "message": "Unauthorized: Invalid API Key"}
        else:
            return {"connected": False, "message": f"API Error: HTTP {response.status_code}"}
    except requests.exceptions.Timeout:
        return {"connected": False, "message": "Connection timeout"}
    except requests.exceptions.RequestException as e:
        return {"connected": False, "message": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"connected": False, "message": f"Unexpected error: {str(e)}"}


def _test_urlscan_api() -> Dict[str, Any]:
    """Test urlscan.io API connection"""
    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key:
        return {"connected": False, "message": "Missing URLSCAN_API_KEY in environment"}
    
    try:
        url = "https://urlscan.io/api/v1/search/"
        params = {"q": "domain:google.com"}
        headers = {"API-Key": api_key}
        response = requests.get(url, params=params, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return {"connected": True, "message": "Successfully connected"}
        elif response.status_code == 401:
            return {"connected": False, "message": "Unauthorized: Invalid API Key"}
        elif response.status_code == 429:
            return {"connected": True, "message": "Successfully connected (Rate Limited)"}
        else:
            return {"connected": False, "message": f"API Error: HTTP {response.status_code}"}
    except requests.exceptions.Timeout:
        return {"connected": False, "message": "Connection timeout"}
    except requests.exceptions.RequestException as e:
        return {"connected": False, "message": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"connected": False, "message": f"Unexpected error: {str(e)}"}


def _test_neiki_api() -> Dict[str, Any]:
    """Test Neiki TIP API connection"""
    api_key = os.getenv("NEIKI_API_KEY")
    if not api_key:
        return {"connected": False, "message": "Missing NEIKI_API_KEY in environment"}
    
    try:
        url = "https://tip.neiki.dev/api/reports/file/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        headers = {"Authorization": api_key, "Content-Type": "application/json"}
        response = requests.get(url, headers=headers, timeout=10)
        
        is_json = "application/json" in response.headers.get("Content-Type", "")

        if response.status_code in [200, 404] and is_json:
            return {"connected": True, "message": "Successfully connected"}
        elif response.status_code in [401, 403]:
            return {"connected": False, "message": "Unauthorized: Invalid API Key"}
        else:
            return {"connected": False, "message": f"API Error: HTTP {response.status_code}"}
    except requests.exceptions.Timeout:
        return {"connected": False, "message": "Connection timeout"}
    except requests.exceptions.RequestException as e:
        return {"connected": False, "message": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"connected": False, "message": f"Unexpected error: {str(e)}"}


# Cache for API status
_api_status_cache = {}
_API_STATUS_CACHE_TTL = timedelta(minutes=10)

@app.get("/api/status")
async def get_api_status(force: bool = False):
    """
    Get API connectivity status for VirusTotal, MalwareBazaar, urlscan.io, and Neiki.
    Results are cached for 10 minutes to prevent rate limiting. Use force=true to bypass cache.
    """
    global _api_status_cache
    now = datetime.now(timezone.utc)
    
    # Check if we have valid cached data
    if not force and _api_status_cache:
        last_checked = _api_status_cache.get("_last_checked")
        if last_checked and (now - last_checked) < _API_STATUS_CACHE_TTL:
            return {k: v for k, v in _api_status_cache.items() if k != "_last_checked"}

    print("DEBUG: Performing live check of API status...")

    vt_status = _test_virustotal_api()
    mb_status = _test_malwarebazaar_api()
    us_status = _test_urlscan_api()
    neiki_status = _test_neiki_api()
    
    status = {
        "virustotal": {
            **vt_status,
            "last_checked": now.isoformat()
        },
        "malwarebazaar": {
            **mb_status,
            "last_checked": now.isoformat()
        },
        "urlscan": {
            **us_status,
            "last_checked": now.isoformat()
        },
        "neiki": {
            **neiki_status,
            "last_checked": now.isoformat()
        }
    }
    
    # Update cache
    _api_status_cache = status.copy()
    _api_status_cache["_last_checked"] = now

    return status


@app.get("/")
async def root():
    return {"message": "TI Analyst's Watchlist API"}


# ============ HEALTH CHECK ENDPOINTS ============

@app.get("/health")
async def health_check():
    """Basic liveness check"""
    return {"status": "healthy"}


@app.get("/ready")
async def readiness_check(db: Session = Depends(get_db)):
    """Readiness check with database connectivity"""
    try:
        # Try to query the database
        from sqlalchemy import text
        result = db.execute(text("SELECT 1"))
        result.fetchone()  # Actually fetch the result
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database not ready: {str(e)}")
