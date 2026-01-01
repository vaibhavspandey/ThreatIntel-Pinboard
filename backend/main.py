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

def _test_virustotal_api() -> bool:
    """Test VirusTotal API connection"""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("DEBUG: VIRUSTOTAL_API_KEY not found in environment")
        return False
    
    try:
        # Test with a simple API call (user info endpoint)
        url = "https://www.virustotal.com/api/v3/users/me"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print("DEBUG: VirusTotal API connection successful")
            return True
        else:
            print(f"DEBUG: VirusTotal API returned status {response.status_code}")
            print(f"DEBUG: Response: {response.text[:200]}")
            return False
    except requests.exceptions.Timeout:
        print("DEBUG: VirusTotal API request timed out")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"DEBUG: VirusTotal API connection error: {str(e)}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"DEBUG: VirusTotal API request error: {str(e)}")
        return False
    except Exception as e:
        print(f"DEBUG: VirusTotal API unexpected error: {str(e)}")
        return False


def _test_malwarebazaar_api() -> bool:
    """Test MalwareBazaar API connection"""
    api_key = os.getenv("MALWAREBAZAAR_API_KEY")
    
    try:
        url = "https://mb-api.abuse.ch/api/v1/"
        # Use a simpler test query that should work
        data = {"query": "get_recent", "selector": "time"}
        headers = {}
        if api_key:
            headers["Auth-Key"] = api_key
        
        response = requests.post(url, data=data, headers=headers, timeout=10)
        
        # 200 = success, 400 = API is reachable but query might be invalid, 401 = Unauthorized but reachable
        if response.status_code in [200, 400, 401]:
            print("DEBUG: MalwareBazaar API connection successful")
            return True
        else:
            print(f"DEBUG: MalwareBazaar API returned status {response.status_code}")
            print(f"DEBUG: Response: {response.text[:200]}")
            return False
    except requests.exceptions.Timeout:
        print("DEBUG: MalwareBazaar API request timed out")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"DEBUG: MalwareBazaar API connection error: {str(e)}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"DEBUG: MalwareBazaar API request error: {str(e)}")
        return False
    except Exception as e:
        print(f"DEBUG: MalwareBazaar API unexpected error: {str(e)}")
        return False


def _test_urlscan_api() -> bool:
    """Test urlscan.io API connection"""
    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key:
        return False
    
    try:
        url = "https://urlscan.io/api/v1/search/"
        params = {"q": "domain:google.com"}
        headers = {"API-Key": api_key}
        response = requests.get(url, params=params, headers=headers, timeout=10)
        
        # 200 = success, 429 = rate limited (still connected)
        if response.status_code in [200, 429]:
            print("DEBUG: urlscan.io API connection successful")
            return True
        else:
            print(f"DEBUG: urlscan.io API returned status {response.status_code}")
            print(f"DEBUG: Response: {response.text[:200]}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"DEBUG: urlscan.io API request error: {str(e)}")
        return False
    except Exception as e:
        print(f"DEBUG: urlscan.io API unexpected error: {str(e)}")
        return False


def _test_neiki_api() -> bool:
    """Test Neiki TIP API connection"""
    api_key = os.getenv("NEIKI_API_KEY")
    if not api_key:
        return False
    
    try:
        url = "https://api.neiki.dev/v1/enrich"
        headers = {"Authorization": f"Bearer {api_key}"}
        data = {"ioc_type": "ip", "ioc_value": "8.8.8.8"}
        response = requests.post(url, headers=headers, json=data, timeout=10)
        
        if response.status_code == 200:
            print("DEBUG: Neiki API connection successful")
            return True
        else:
            print(f"DEBUG: Neiki API returned status {response.status_code}")
            print(f"DEBUG: Response: {response.text[:200]}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"DEBUG: Neiki API request error: {str(e)}")
        return False
    except Exception as e:
        print(f"DEBUG: Neiki API unexpected error: {str(e)}")
        return False


@app.get("/api/status")
async def get_api_status():
    """
    Get API connectivity status for VirusTotal and MalwareBazaar.
    """
    now = datetime.now(timezone.utc)
    
    # Need to check APIs
    print("DEBUG: Checking API status...")
    vt_connected = _test_virustotal_api()
    mb_connected = _test_malwarebazaar_api()
    us_connected = _test_urlscan_api()
    neiki_connected = _test_neiki_api()
    
    status = {
        "virustotal": {
            "connected": vt_connected,
            "last_checked": now.isoformat()
        },
        "malwarebazaar": {
            "connected": mb_connected,
            "last_checked": now.isoformat()
        },
        "urlscan": {
            "connected": us_connected,
            "last_checked": now.isoformat()
        },
        "neiki": {
            "connected": neiki_connected,
            "last_checked": now.isoformat()
        }
    }
    
    return status


@app.get("/api/test-neiki")
async def test_neiki():
    """Temporary endpoint for debugging Neiki API"""
    connected = _test_neiki_api()
    return {"neiki_connected": connected}


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
