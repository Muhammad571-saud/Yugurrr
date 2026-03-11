from fastapi import FastAPI, APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, status, File, UploadFile, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from shapely.geometry import Polygon, mapping, shape
from shapely.ops import unary_union
import json
import base64
import asyncio

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'starrun_secret_key_2025_very_secure')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24 * 7  # 7 days

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
security = HTTPBearer()

# Admin password (hashed)
ADMIN_PASSWORD = "admin&N91%adca@3/as"

# Predefined colors (30 colors)
PREDEFINED_COLORS = [
    "#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4", "#FFEAA7",
    "#DDA0DD", "#98D8C8", "#F7DC6F", "#BB8FCE", "#85C1E9",
    "#F8B500", "#00CED1", "#FF69B4", "#32CD32", "#FFD700",
    "#FF4500", "#8A2BE2", "#00FA9A", "#DC143C", "#1E90FF",
    "#FF1493", "#7FFF00", "#D2691E", "#6495ED", "#FF7F50",
    "#9ACD32", "#EE82EE", "#40E0D0", "#FA8072", "#87CEEB"
]

# Create the main app
app = FastAPI(title="STAR RUN API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== MODELS ====================

class UserCreate(BaseModel):
    name: str
    phone: str
    password: str
    color: str
    profile_image: Optional[str] = None  # Base64 encoded

class UserLogin(BaseModel):
    phone: str
    password: str

class UserResponse(BaseModel):
    id: str
    name: str
    phone_masked: str
    color: str
    profile_image: Optional[str] = None
    total_distance: float = 0.0
    total_territory: float = 0.0
    created_at: datetime
    is_blocked: bool = False

class UserProfileUpdate(BaseModel):
    color: Optional[str] = None
    profile_image: Optional[str] = None
    name: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class RunCreate(BaseModel):
    route: List[Dict[str, float]]  # [{lat, lng, timestamp, accuracy}]
    distance: float
    duration: int  # seconds
    avg_speed: float

class TerritoryResponse(BaseModel):
    id: str
    user_id: str
    user_name: str
    user_color: str
    polygon: Dict[str, Any]  # GeoJSON
    area: float
    created_at: datetime
    captured_from: Optional[str] = None

class RunResponse(BaseModel):
    id: str
    user_id: str
    route: List[Dict[str, float]]
    distance: float
    duration: int
    avg_speed: float
    created_at: datetime
    territory_created: bool = False
    territory_area: float = 0.0

class LeaderboardEntry(BaseModel):
    rank: int
    user_id: str
    name: str
    color: str
    profile_image: Optional[str] = None
    total_territory: float
    total_distance: float

class WarningCreate(BaseModel):
    user_id: Optional[str] = None  # None for broadcast
    message: str

class AdminStats(BaseModel):
    total_users: int
    total_territories: int
    total_distance: float
    monthly_top_runners: List[Dict]
    all_time_top_runners: List[Dict]

# ==================== HELPER FUNCTIONS ====================

def mask_phone(phone: str) -> str:
    """Mask phone number for privacy: +998 ** *** ** **"""
    if len(phone) < 9:
        return "+998 ** *** ** **"
    # Keep only last 2 digits visible
    return f"+998 ** *** ** {phone[-2:]}"

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        if user.get("is_blocked", False):
            raise HTTPException(status_code=403, detail="User is blocked")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def verify_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("is_admin") != True:
            raise HTTPException(status_code=403, detail="Admin access required")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def normalize_phone(phone: str) -> str:
    """Normalize phone number to +998 format"""
    phone = phone.strip().replace(" ", "").replace("-", "")
    if phone.startswith("+998"):
        return phone
    if phone.startswith("998"):
        return "+" + phone
    if phone.startswith("0"):
        return "+998" + phone[1:]
    return "+998" + phone

def route_to_polygon(route: List[Dict[str, float]]) -> Optional[Dict]:
    """Convert GPS route to GeoJSON polygon by creating a buffer around the route"""
    if len(route) < 3:
        return None
    
    from shapely.geometry import LineString
    from shapely.ops import unary_union
    
    # Extract coordinates (lng, lat format for GeoJSON)
    coords = [(point["lng"], point["lat"]) for point in route]
    
    try:
        # Create a LineString from the route
        line = LineString(coords)
        
        if not line.is_valid or line.is_empty:
            return None
        
        # Buffer the line to create a polygon
        # Buffer value is in degrees, roughly 0.00005 ≈ 5 meters
        buffer_distance = 0.00008  # ~8 meters buffer on each side
        buffered = line.buffer(buffer_distance, cap_style=1, join_style=1)  # round caps and joins
        
        if not buffered.is_valid:
            buffered = buffered.buffer(0)
        
        if not buffered.is_valid or buffered.is_empty:
            return None
        
        # If the route forms a closed loop, we can also include the interior
        if coords[0] != coords[-1]:
            # Check if start and end are close enough to form a loop
            start = coords[0]
            end = coords[-1]
            dist = ((start[0] - end[0])**2 + (start[1] - end[1])**2)**0.5
            
            if dist < 0.0005:  # ~50 meters - close enough to form a loop
                # Close the route and create polygon from the enclosed area
                closed_coords = coords + [coords[0]]
                try:
                    enclosed = Polygon(closed_coords)
                    if enclosed.is_valid and not enclosed.is_empty:
                        # Combine the buffered path with the enclosed area
                        combined = unary_union([buffered, enclosed])
                        if combined.is_valid:
                            buffered = combined
                except:
                    pass  # Keep just the buffered version
        
        # Simplify to reduce points while keeping shape
        simplified = buffered.simplify(0.00001, preserve_topology=True)
        
        if simplified.is_valid and not simplified.is_empty:
            return mapping(simplified)
        
        return mapping(buffered)
        
    except Exception as e:
        logger.error(f"Polygon creation error: {e}")
        return None

def calculate_area_sqm(polygon_geojson: Dict) -> float:
    """Calculate approximate area in square meters from GeoJSON polygon"""
    try:
        poly = shape(polygon_geojson)
        # Approximate conversion: 1 degree ≈ 111,320 meters at equator
        # For Uzbekistan (around 41°N), factor is about 84,000 for longitude
        center_lat = sum([c[1] for c in poly.exterior.coords]) / len(poly.exterior.coords)
        import math
        lat_factor = 111320  # meters per degree latitude
        lng_factor = 111320 * math.cos(math.radians(center_lat))  # meters per degree longitude
        
        # Simple area calculation (rough approximation)
        area_deg = poly.area
        area_sqm = area_deg * lat_factor * lng_factor
        return round(area_sqm, 2)
    except Exception as e:
        logger.error(f"Area calculation error: {e}")
        return 0.0

async def check_territory_capture(new_polygon: Dict, user_id: str) -> List[Dict]:
    """Check if new territory captures any existing territories"""
    captured = []
    new_shape = shape(new_polygon)
    
    try:
        # Find all territories that might intersect
        all_territories = await db.territories.find({
            "user_id": {"$ne": user_id},
            "polygon": {
                "$geoIntersects": {
                    "$geometry": new_polygon
                }
            }
        }).to_list(1000)
        
        for territory in all_territories:
            try:
                existing_shape = shape(territory["polygon"])
                intersection = new_shape.intersection(existing_shape)
                
                if not intersection.is_empty:
                    overlap_ratio = intersection.area / existing_shape.area
                    
                    # If 30% or more is captured
                    if overlap_ratio >= 0.3:
                        captured.append({
                            "territory_id": territory["id"],
                            "previous_owner_id": territory["user_id"],
                            "overlap_ratio": overlap_ratio
                        })
            except Exception as e:
                logger.error(f"Intersection check error: {e}")
                continue
    except Exception as e:
        logger.error(f"Territory capture check error: {e}")
    
    return captured

# ==================== WEBSOCKET MANAGER ====================

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        logger.info(f"WebSocket connected: {user_id}")
    
    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
            logger.info(f"WebSocket disconnected: {user_id}")
    
    async def send_personal(self, user_id: str, message: dict):
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_json(message)
            except Exception as e:
                logger.error(f"Send error to {user_id}: {e}")
    
    async def broadcast(self, message: dict, exclude: Optional[str] = None):
        for user_id, connection in list(self.active_connections.items()):
            if user_id != exclude:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Broadcast error to {user_id}: {e}")

manager = ConnectionManager()

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/signup", response_model=TokenResponse)
async def signup(user: UserCreate):
    # Normalize phone
    phone = normalize_phone(user.phone)
    
    # Check if phone exists
    existing = await db.users.find_one({"phone": phone})
    if existing:
        raise HTTPException(status_code=400, detail="Phone number already registered")
    
    # Validate color
    if user.color not in PREDEFINED_COLORS:
        raise HTTPException(status_code=400, detail="Invalid color selection")
    
    # Create user
    user_id = str(uuid.uuid4())
    user_doc = {
        "id": user_id,
        "name": user.name,
        "phone": phone,
        "password_hash": hash_password(user.password),
        "color": user.color,
        "profile_image": user.profile_image,
        "total_distance": 0.0,
        "total_territory": 0.0,
        "created_at": datetime.utcnow(),
        "is_blocked": False,
        "is_admin": False
    }
    
    await db.users.insert_one(user_doc)
    
    # Create token
    token = create_access_token({"sub": user_id})
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user_id,
            name=user.name,
            phone_masked=mask_phone(phone),
            color=user.color,
            profile_image=user.profile_image,
            total_distance=0.0,
            total_territory=0.0,
            created_at=user_doc["created_at"],
            is_blocked=False
        )
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    phone = normalize_phone(credentials.phone)
    
    user = await db.users.find_one({"phone": phone})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if user.get("is_blocked", False):
        raise HTTPException(status_code=403, detail="Account is blocked")
    
    token = create_access_token({"sub": user["id"]})
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"],
            name=user["name"],
            phone_masked=mask_phone(user["phone"]),
            color=user["color"],
            profile_image=user.get("profile_image"),
            total_distance=user.get("total_distance", 0.0),
            total_territory=user.get("total_territory", 0.0),
            created_at=user["created_at"],
            is_blocked=user.get("is_blocked", False)
        )
    )

@api_router.post("/auth/admin-login", response_model=TokenResponse)
async def admin_login(password: str):
    if password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    
    token = create_access_token({"sub": "admin", "is_admin": True})
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id="admin",
            name="Administrator",
            phone_masked="+998 ** *** ** **",
            color="#000000",
            total_distance=0.0,
            total_territory=0.0,
            created_at=datetime.utcnow(),
            is_blocked=False
        )
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        id=current_user["id"],
        name=current_user["name"],
        phone_masked=mask_phone(current_user["phone"]),
        color=current_user["color"],
        profile_image=current_user.get("profile_image"),
        total_distance=current_user.get("total_distance", 0.0),
        total_territory=current_user.get("total_territory", 0.0),
        created_at=current_user["created_at"],
        is_blocked=current_user.get("is_blocked", False)
    )

# ==================== USER ROUTES ====================

@api_router.put("/users/profile", response_model=UserResponse)
async def update_profile(update: UserProfileUpdate, current_user: dict = Depends(get_current_user)):
    update_data = {}
    
    if update.color and update.color in PREDEFINED_COLORS:
        update_data["color"] = update.color
    
    if update.profile_image is not None:
        update_data["profile_image"] = update.profile_image
    
    if update.name:
        update_data["name"] = update.name
    
    if update_data:
        await db.users.update_one(
            {"id": current_user["id"]},
            {"$set": update_data}
        )
        
        # Update territories color if changed
        if "color" in update_data:
            await db.territories.update_many(
                {"user_id": current_user["id"]},
                {"$set": {"user_color": update_data["color"]}}
            )
    
    user = await db.users.find_one({"id": current_user["id"]})
    return UserResponse(
        id=user["id"],
        name=user["name"],
        phone_masked=mask_phone(user["phone"]),
        color=user["color"],
        profile_image=user.get("profile_image"),
        total_distance=user.get("total_distance", 0.0),
        total_territory=user.get("total_territory", 0.0),
        created_at=user["created_at"],
        is_blocked=user.get("is_blocked", False)
    )

@api_router.get("/colors", response_model=List[str])
async def get_colors():
    return PREDEFINED_COLORS

# ==================== RUN ROUTES ====================

@api_router.post("/runs", response_model=RunResponse)
async def create_run(run: RunCreate, current_user: dict = Depends(get_current_user)):
    run_id = str(uuid.uuid4())
    
    # Create polygon from route
    polygon = route_to_polygon(run.route)
    territory_created = False
    territory_area = 0.0
    
    run_doc = {
        "id": run_id,
        "user_id": current_user["id"],
        "route": run.route,
        "distance": run.distance,
        "duration": run.duration,
        "avg_speed": run.avg_speed,
        "created_at": datetime.utcnow(),
        "territory_created": False,
        "territory_area": 0.0
    }
    
    if polygon:
        # Calculate area
        territory_area = calculate_area_sqm(polygon)
        
        if territory_area >= 50:  # Minimum 50 sq meters
            territory_id = str(uuid.uuid4())
            
            # Check for territory captures
            captured = await check_territory_capture(polygon, current_user["id"])
            
            # Process captures
            for capture in captured:
                # Transfer ownership
                await db.territories.update_one(
                    {"id": capture["territory_id"]},
                    {
                        "$set": {
                            "user_id": current_user["id"],
                            "user_name": current_user["name"],
                            "user_color": current_user["color"],
                            "captured_from": capture["previous_owner_id"],
                            "captured_at": datetime.utcnow()
                        }
                    }
                )
                
                # Get captured territory for area update
                captured_territory = await db.territories.find_one({"id": capture["territory_id"]})
                
                # Update previous owner's total territory
                if captured_territory:
                    await db.users.update_one(
                        {"id": capture["previous_owner_id"]},
                        {"$inc": {"total_territory": -captured_territory.get("area", 0)}}
                    )
                    
                    # Add to new owner's total
                    await db.users.update_one(
                        {"id": current_user["id"]},
                        {"$inc": {"total_territory": captured_territory.get("area", 0)}}
                    )
                
                # Log capture event
                await db.capture_events.insert_one({
                    "id": str(uuid.uuid4()),
                    "territory_id": capture["territory_id"],
                    "new_owner_id": current_user["id"],
                    "previous_owner_id": capture["previous_owner_id"],
                    "overlap_ratio": capture["overlap_ratio"],
                    "created_at": datetime.utcnow()
                })
                
                # Send notifications (mock for MVP)
                await db.notifications.insert_one({
                    "id": str(uuid.uuid4()),
                    "user_id": capture["previous_owner_id"],
                    "type": "territory_lost",
                    "message": f"{current_user['name']} captured your territory!",
                    "read": False,
                    "created_at": datetime.utcnow()
                })
                
                # Broadcast territory update
                await manager.broadcast({
                    "type": "territory_captured",
                    "territory_id": capture["territory_id"],
                    "new_owner": current_user["name"],
                    "new_color": current_user["color"]
                })
            
            # Create new territory
            territory_doc = {
                "id": territory_id,
                "user_id": current_user["id"],
                "user_name": current_user["name"],
                "user_color": current_user["color"],
                "polygon": polygon,
                "area": territory_area,
                "created_at": datetime.utcnow(),
                "captured_from": None
            }
            
            await db.territories.insert_one(territory_doc)
            territory_created = True
            
            # Update user's total territory
            await db.users.update_one(
                {"id": current_user["id"]},
                {"$inc": {"total_territory": territory_area}}
            )
            
            run_doc["territory_created"] = True
            run_doc["territory_area"] = territory_area
            
            # Broadcast new territory
            await manager.broadcast({
                "type": "new_territory",
                "territory": {
                    "id": territory_id,
                    "user_name": current_user["name"],
                    "user_color": current_user["color"],
                    "polygon": polygon,
                    "area": territory_area
                }
            })
    
    # Update user's total distance
    await db.users.update_one(
        {"id": current_user["id"]},
        {"$inc": {"total_distance": run.distance}}
    )
    
    await db.runs.insert_one(run_doc)
    
    return RunResponse(**run_doc)

@api_router.get("/runs", response_model=List[RunResponse])
async def get_my_runs(current_user: dict = Depends(get_current_user)):
    runs = await db.runs.find({"user_id": current_user["id"]}).sort("created_at", -1).to_list(100)
    return [RunResponse(**run) for run in runs]

# ==================== TERRITORY ROUTES ====================

@api_router.get("/territories", response_model=List[TerritoryResponse])
async def get_all_territories():
    territories = await db.territories.find().to_list(1000)
    return [TerritoryResponse(**t) for t in territories]

@api_router.get("/territories/user/{user_id}", response_model=List[TerritoryResponse])
async def get_user_territories(user_id: str):
    territories = await db.territories.find({"user_id": user_id}).to_list(100)
    return [TerritoryResponse(**t) for t in territories]

# ==================== LEADERBOARD ROUTES ====================

@api_router.get("/leaderboard", response_model=List[LeaderboardEntry])
async def get_leaderboard():
    users = await db.users.find({"is_blocked": {"$ne": True}}).sort("total_territory", -1).to_list(100)
    
    leaderboard = []
    for rank, user in enumerate(users, 1):
        leaderboard.append(LeaderboardEntry(
            rank=rank,
            user_id=user["id"],
            name=user["name"],
            color=user["color"],
            profile_image=user.get("profile_image"),
            total_territory=user.get("total_territory", 0.0),
            total_distance=user.get("total_distance", 0.0)
        ))
    
    return leaderboard

# ==================== NOTIFICATION ROUTES ====================

@api_router.get("/notifications")
async def get_notifications(current_user: dict = Depends(get_current_user)):
    notifications = await db.notifications.find(
        {"user_id": current_user["id"]}
    ).sort("created_at", -1).to_list(50)
    # Remove MongoDB _id field
    return [{
        "id": n["id"],
        "user_id": n["user_id"],
        "type": n["type"],
        "message": n["message"],
        "read": n["read"],
        "created_at": n["created_at"].isoformat() if hasattr(n["created_at"], 'isoformat') else str(n["created_at"])
    } for n in notifications]

@api_router.put("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, current_user: dict = Depends(get_current_user)):
    await db.notifications.update_one(
        {"id": notification_id, "user_id": current_user["id"]},
        {"$set": {"read": True}}
    )
    return {"success": True}

# ==================== ADMIN ROUTES ====================

@api_router.get("/admin/stats", response_model=AdminStats)
async def get_admin_stats(admin: dict = Depends(verify_admin)):
    total_users = await db.users.count_documents({})
    total_territories = await db.territories.count_documents({})
    
    # Calculate total distance
    pipeline = [{"$group": {"_id": None, "total": {"$sum": "$total_distance"}}}]
    result = await db.users.aggregate(pipeline).to_list(1)
    total_distance = result[0]["total"] if result else 0
    
    # Monthly top runners
    start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_pipeline = [
        {"$match": {"created_at": {"$gte": start_of_month}}},
        {"$group": {"_id": "$user_id", "total_distance": {"$sum": "$distance"}}},
        {"$sort": {"total_distance": -1}},
        {"$limit": 10}
    ]
    monthly_results = await db.runs.aggregate(monthly_pipeline).to_list(10)
    
    monthly_top = []
    for item in monthly_results:
        user = await db.users.find_one({"id": item["_id"]})
        if user:
            monthly_top.append({
                "user_id": user["id"],
                "name": user["name"],
                "phone_masked": mask_phone(user["phone"]),
                "total_distance": item["total_distance"],
                "total_territory": user.get("total_territory", 0),
                "created_at": user["created_at"].isoformat()
            })
    
    # All-time top runners
    all_time_top = []
    top_users = await db.users.find().sort("total_distance", -1).limit(10).to_list(10)
    for user in top_users:
        all_time_top.append({
            "user_id": user["id"],
            "name": user["name"],
            "phone_masked": mask_phone(user["phone"]),
            "total_distance": user.get("total_distance", 0),
            "total_territory": user.get("total_territory", 0),
            "created_at": user["created_at"].isoformat()
        })
    
    return AdminStats(
        total_users=total_users,
        total_territories=total_territories,
        total_distance=total_distance,
        monthly_top_runners=monthly_top,
        all_time_top_runners=all_time_top
    )

@api_router.get("/admin/users")
async def get_admin_users(admin: dict = Depends(verify_admin)):
    users = await db.users.find().to_list(1000)
    return [{
        "id": u["id"],
        "name": u["name"],
        "phone": u["phone"],  # Admin uchun to'liq telefon raqam
        "color": u["color"],
        "total_distance": u.get("total_distance", 0),
        "total_territory": u.get("total_territory", 0),
        "created_at": u["created_at"].isoformat(),
        "is_blocked": u.get("is_blocked", False)
    } for u in users]

@api_router.post("/admin/warn")
async def send_warning(warning: WarningCreate, admin: dict = Depends(verify_admin)):
    if warning.user_id:
        # Send to specific user
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": warning.user_id,
            "type": "admin_warning",
            "message": warning.message,
            "read": False,
            "created_at": datetime.utcnow()
        })
        
        await manager.send_personal(warning.user_id, {
            "type": "admin_warning",
            "message": warning.message
        })
    else:
        # Broadcast to all users
        users = await db.users.find().to_list(1000)
        for user in users:
            await db.notifications.insert_one({
                "id": str(uuid.uuid4()),
                "user_id": user["id"],
                "type": "admin_warning",
                "message": warning.message,
                "read": False,
                "created_at": datetime.utcnow()
            })
        
        await manager.broadcast({
            "type": "admin_warning",
            "message": warning.message
        })
    
    return {"success": True}

@api_router.post("/admin/block/{user_id}")
async def block_user(user_id: str, admin: dict = Depends(verify_admin)):
    await db.users.update_one(
        {"id": user_id},
        {"$set": {"is_blocked": True}}
    )
    
    # Send notification
    await db.notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "type": "account_blocked",
        "message": "Your account has been blocked by administrator",
        "read": False,
        "created_at": datetime.utcnow()
    })
    
    await manager.send_personal(user_id, {
        "type": "account_blocked",
        "message": "Your account has been blocked"
    })
    
    return {"success": True}

@api_router.post("/admin/unblock/{user_id}")
async def unblock_user(user_id: str, admin: dict = Depends(verify_admin)):
    await db.users.update_one(
        {"id": user_id},
        {"$set": {"is_blocked": False}}
    )
    return {"success": True}

# ==================== WEBSOCKET ROUTES ====================

@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=4001)
            return
        
        await manager.connect(websocket, user_id)
        
        try:
            while True:
                data = await websocket.receive_json()
                
                # Handle real-time location updates
                if data.get("type") == "location_update":
                    # Broadcast to other users (for live tracking feature if needed)
                    await manager.broadcast({
                        "type": "runner_location",
                        "user_id": user_id,
                        "location": data.get("location")
                    }, exclude=user_id)
                
        except WebSocketDisconnect:
            manager.disconnect(user_id)
    except JWTError:
        await websocket.close(code=4001)

# ==================== DATABASE INDEXES ====================

@app.on_event("startup")
async def create_indexes():
    try:
        # User indexes
        await db.users.create_index("id", unique=True)
        await db.users.create_index("phone", unique=True)
        
        # Territory indexes with 2dsphere for GeoJSON
        await db.territories.create_index("id", unique=True)
        await db.territories.create_index("user_id")
        await db.territories.create_index([("polygon", "2dsphere")])
        
        # Run indexes
        await db.runs.create_index("id", unique=True)
        await db.runs.create_index("user_id")
        await db.runs.create_index("created_at")
        
        # Notification indexes
        await db.notifications.create_index("id", unique=True)
        await db.notifications.create_index("user_id")
        
        logger.info("Database indexes created successfully")
    except Exception as e:
        logger.error(f"Error creating indexes: {e}")

# Include the router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
