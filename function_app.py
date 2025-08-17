import os
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

import azure.functions as func
from azure.functions import FunctionApp, HttpRequest, HttpResponse, AuthLevel
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from azure.cosmos import CosmosClient, exceptions, PartitionKey
from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    status,
    UploadFile,
    File,
    Form,
    APIRouter,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing_extensions import Annotated

# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def db_logger_info(msg):
    logger.info(f"[DB] {msg}")


def db_logger_warning(msg):
    logger.warning(f"[DB-WARN] {msg}")


def db_logger_error(msg):
    logger.error(f"[DB-ERR] {msg}")


def log_error(e, op, ctx):
    logger.error(f"[ERROR] {op}: {e} | {ctx}")


def log_auth_event(event, email, success, ctx):
    logger.info(f"[AUTH] {event} for {email}: {'OK' if success else 'FAIL'} | {ctx}")


def log_database_operation(op, table, ctx):
    logger.info(f"[DB-OP] {op} on {table} | {ctx}")


# Configuration
CONFIG = {
    "AZURE_STORAGE_CONNECTION_STRING": os.getenv("AZURE_STORAGE_CONNECTION_STRING", ""),
    "AZURE_STORAGE_CONTAINER": os.getenv("AZURE_STORAGE_CONTAINER", "videos"),
    "AZURE_STORAGE_THUMBNAIL_CONTAINER": os.getenv(
        "AZURE_STORAGE_THUMBNAIL_CONTAINER", "thumbnails"
    ),
    "COSMOS_DB_ENDPOINT": os.getenv(
        "COSMOS_DB_ENDPOINT", "https://sql-sa6ecv2s2ohmg.documents.azure.com:443/"
    ),
    "COSMOS_DB_KEY": os.getenv("COSMOS_DB_KEY", ""),
    "COSMOS_DB_DATABASE": os.getenv("COSMOS_DB_DATABASE", "proj-utik"),
    "JWT_SECRET_KEY": os.getenv("JWT_SECRET_KEY", "secret-key-for-testing"),
    "JWT_ALGORITHM": os.getenv("JWT_ALGORITHM", "HS256"),
    "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": int(
        os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    ),
    # CORS Configuration
    "FRONTEND_URL": os.getenv("FRONTEND_URL", "http://localhost:3000"),
    "ENVIRONMENT": os.getenv("ENVIRONMENT", "production"),
}


# CORS Origins Configuration
def get_allowed_origins():
    """Get allowed CORS origins - single origin from environment"""
    origins = []

    # Primary frontend URL from environment
    frontend_url = CONFIG["FRONTEND_URL"]
    if frontend_url:
        origins.append(frontend_url)

    # Only add localhost for development environment
    if CONFIG["ENVIRONMENT"].lower() == "development":
        origins.append("http://localhost:3000")
        origins.append("http://127.0.0.1:3000")
        origins.append("http://localhost:7071")

    # Remove duplicates and ensure we have at least one origin
    origins = list(set(filter(None, origins)))

    if not origins:
        logger.warning("No CORS origins configured! Adding localhost fallback.")
        origins = ["http://localhost:3000"]

    logger.info(f"CORS allowed origins: {origins}")
    return origins


ALLOWED_ORIGINS = get_allowed_origins()


# CosmosDB Client
class CosmosDBClient:
    def __init__(self):
        self.endpoint = CONFIG["COSMOS_DB_ENDPOINT"]
        self.key = CONFIG["COSMOS_DB_KEY"]
        self.database_name = CONFIG["COSMOS_DB_DATABASE"]

        if not self.key:
            raise ValueError("COSMOS_DB_KEY environment variable is required")

        self.client = CosmosClient(self.endpoint, self.key)
        self.database = self.client.get_database_client(self.database_name)
        self.containers = {
            "users": PartitionKey(path="/email"),
            "videos": PartitionKey(path="/id"),
            "comments": PartitionKey(path="/video_id"),
            "ratings": PartitionKey(path="/video_id"),
        }
        self.container_clients = {}
        self._initialize_containers()

    def _initialize_containers(self):
        """Initialize container clients, creating containers if they don't exist"""
        for container_name, partition_key in self.containers.items():
            try:
                # Try to create container if it doesn't exist
                db_logger_info(
                    f"Initializing {container_name} container with partition key {partition_key.path}"
                )
                created_container = self.database.create_container_if_not_exists(
                    id=container_name, partition_key=partition_key
                )
                self.container_clients[container_name] = created_container
                db_logger_info(
                    f"{container_name.capitalize()} container initialized successfully"
                )
            except Exception as create_error:
                log_error(
                    create_error,
                    f"container_initialization_{container_name}",
                    {"container": container_name, "partition_key": partition_key.path},
                )
                # Don't raise here, just log the error and continue
                db_logger_warning(
                    f"Failed to initialize {container_name} container: {str(create_error)}"
                )

    def _create_containers(self):
        """Legacy method - containers are now created in _initialize_containers"""
        pass

    def get_container(self, container_name):
        """Get container client, creating it if it doesn't exist"""
        if container_name in self.container_clients:
            return self.container_clients[container_name]
        elif container_name in self.containers:
            # Container is defined but not initialized, try to create it
            try:
                partition_key = self.containers[container_name]
                db_logger_info(f"Creating missing {container_name} container on-demand")
                created_container = self.database.create_container_if_not_exists(
                    id=container_name, partition_key=partition_key
                )
                self.container_clients[container_name] = created_container
                db_logger_info(
                    f"{container_name.capitalize()} container created on-demand"
                )
                return created_container
            except Exception as e:
                log_error(
                    e,
                    f"on_demand_container_creation_{container_name}",
                    {"container": container_name},
                )
                raise ValueError(
                    f"Failed to create container '{container_name}': {str(e)}"
                )
        else:
            raise ValueError(
                f"Container '{container_name}' is not defined in the schema"
            )


# Initialize Cosmos client
try:
    cosmos_client = CosmosDBClient()
except Exception as e:
    logger.error(f"Failed to initialize CosmosDB client: {str(e)}")
    cosmos_client = None

# Initialize Blob Storage client
try:
    if CONFIG["AZURE_STORAGE_CONNECTION_STRING"]:
        blob_service_client = BlobServiceClient.from_connection_string(
            CONFIG["AZURE_STORAGE_CONNECTION_STRING"]
        )
        logger.info("Azure Blob Storage client initialized successfully")
    else:
        blob_service_client = None
        logger.warning("Azure Storage connection string not provided")
except Exception as e:
    logger.error(f"Failed to initialize Blob Storage client: {str(e)}")
    blob_service_client = None


# Azure Storage Helper Functions
def upload_video_to_blob(
    file_data: bytes, filename: str, content_type: str = "video/mp4"
):
    """Upload video file to Azure Blob Storage"""
    if not blob_service_client:
        raise HTTPException(status_code=500, detail="Blob storage not configured")

    try:
        import os

        file_extension = os.path.splitext(filename)[1]
        blob_name = f"{uuid.uuid4()}{file_extension}"

        # Upload to videos container
        container_client = blob_service_client.get_container_client(
            CONFIG["AZURE_STORAGE_CONTAINER"]
        )
        blob_client = container_client.get_blob_client(blob_name)
        blob_client.upload_blob(file_data, content_type=content_type, overwrite=True)

        blob_url = blob_client.url
        logger.info(f"Video uploaded successfully: {blob_name}")
        return blob_name, blob_url
    except Exception as e:
        logger.error(f"Failed to upload video to blob storage: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to upload video file")


def upload_thumbnail_to_blob(
    file_data: bytes, filename: str, content_type: str = "image/jpeg"
):
    """Upload thumbnail file to Azure Blob Storage"""
    if not blob_service_client:
        return None, None

    try:
        import os

        file_extension = os.path.splitext(filename)[1]
        blob_name = f"{uuid.uuid4()}{file_extension}"

        # Upload to thumbnails container (or same container with different prefix)
        container_name = (
            "thumbnails"
            if "thumbnails" in CONFIG.get("AZURE_STORAGE_THUMBNAIL_CONTAINER", "")
            else CONFIG["AZURE_STORAGE_CONTAINER"]
        )
        container_client = blob_service_client.get_container_client(container_name)
        blob_client = container_client.get_blob_client(blob_name)
        blob_client.upload_blob(file_data, content_type=content_type, overwrite=True)

        blob_url = blob_client.url
        logger.info(f"Thumbnail uploaded successfully: {blob_name}")
        return blob_name, blob_url
    except Exception as e:
        logger.error(f"Failed to upload thumbnail: {str(e)}")
        return None, None


def get_secure_blob_url(blob_name: str, container_name: str, expiry_hours: int = 24):
    """Generate a secure URL with SAS token for blob access"""
    if not blob_service_client:
        return None

    try:
        from datetime import timedelta

        blob_client = blob_service_client.get_blob_client(
            container=container_name, blob=blob_name
        )

        # Try to generate SAS token if we have the account key
        try:
            sas_token = generate_blob_sas(
                account_name=blob_service_client.account_name,
                container_name=container_name,
                blob_name=blob_name,
                account_key=blob_service_client.credential.account_key,
                permission=BlobSasPermissions(read=True),
                expiry=datetime.utcnow() + timedelta(hours=expiry_hours),
            )
            return f"{blob_client.url}?{sas_token}"
        except Exception as sas_error:
            logger.warning(f"Could not generate SAS token: {str(sas_error)}")
            return blob_client.url

    except Exception as e:
        logger.error(f"Failed to generate secure URL: {str(e)}")
        return None


# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/token")
ACCESS_TOKEN_EXPIRE_MINUTES = CONFIG["JWT_ACCESS_TOKEN_EXPIRE_MINUTES"]


# Pydantic Models
class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    role: str
    createdAt: datetime
    updatedAt: datetime


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


class User(UserBase):
    id: str
    role: str = "CONSUMER"
    disabled: bool = False


class UserInDB(User):
    hashed_password: str


class VideoMetadata(BaseModel):
    title: str
    publisher: str
    producer: str
    genre: str
    age_rating: str = Field(..., pattern="^(G|PG|PG-13|R|18\\+)$")
    description: Optional[str] = None
    tags: Optional[List[str]] = None


class Video(VideoMetadata):
    id: str
    blob_url: str
    upload_date: datetime
    uploader_id: str
    views: int = 0
    average_rating: Optional[float] = None


# Authentication Utilities
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, CONFIG["JWT_SECRET_KEY"], algorithm=CONFIG["JWT_ALGORITHM"]
    )
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, CONFIG["JWT_SECRET_KEY"], algorithms=[CONFIG["JWT_ALGORITHM"]]
        )
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    if not cosmos_client:
        raise HTTPException(status_code=500, detail="Database connection failed")

    users_container = cosmos_client.get_container("users")
    try:
        query = "SELECT * FROM c WHERE c.email = @email"
        parameters = [{"name": "@email", "value": token_data.email}]
        users = list(
            users_container.query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True,
            )
        )
        if not users:
            raise credentials_exception

        user = users[0]
        password_hash = user.get("passwordHash") or user.get("hashed_password")

        return UserInDB(
            id=user["id"],
            email=user["email"],
            role=user.get("role", "CONSUMER"),
            disabled=user.get("disabled", False),
            hashed_password=password_hash,
        )
    except Exception:
        raise credentials_exception


# FastAPI app
fastapi_app = FastAPI(title="Video Sharing API", version="1.0.0")

# CORS middleware - Secure single-origin configuration
fastapi_app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # 🔒 Single origin from environment only!
    allow_credentials=True,  # ✅ Safe with specific origins
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health check endpoint
@fastapi_app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "cosmos_connected": cosmos_client is not None,
    }


# Auth router
auth_router = APIRouter()


@auth_router.post("/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    if not cosmos_client:
        raise HTTPException(status_code=500, detail="Database connection failed")

    users_container = cosmos_client.get_container("users")
    logger.info(f"Register attempt for email: {user_data.email}")

    try:
        # Check if user already exists
        query = "SELECT * FROM c WHERE c.email = @email"
        parameters = [{"name": "@email", "value": user_data.email}]
        existing_users = list(
            users_container.query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True,
            )
        )

        if existing_users:
            logger.warning(
                f"Registration failed: Email already exists: {user_data.email}"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        # Create new user
        hashed_password = get_password_hash(user_data.password)
        user_id = str(uuid.uuid4())
        now = datetime.utcnow()

        user_doc = {
            "id": user_id,
            "email": user_data.email,
            "passwordHash": hashed_password,
            "role": "CONSUMER",  # All public registrations are consumers
            "disabled": False,
            "createdAt": now.isoformat(),
            "updatedAt": now.isoformat(),
        }

        created_user = users_container.create_item(user_doc)
        logger.info(
            f"User registered: {created_user['email']} (id: {created_user['id']})"
        )

        return UserResponse(
            id=created_user["id"],
            email=created_user["email"],
            role=created_user["role"],
            createdAt=datetime.fromisoformat(created_user["createdAt"]),
            updatedAt=datetime.fromisoformat(created_user["updatedAt"]),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error for {user_data.email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}",
        )


@auth_router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if not cosmos_client:
        raise HTTPException(status_code=500, detail="Database connection failed")

    users_container = cosmos_client.get_container("users")
    logger.info(f"Login attempt for email: {form_data.username}")

    try:
        # Find user by email
        query = "SELECT * FROM c WHERE c.email = @email"
        parameters = [{"name": "@email", "value": form_data.username}]
        users = list(
            users_container.query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True,
            )
        )

        if not users:
            logger.warning(
                f"Login failed: User not found for email: {form_data.username}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = users[0]
        password_hash = user.get("passwordHash") or user.get("hashed_password")

        if not password_hash:
            logger.error(f"No password hash found for user: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not verify_password(form_data.password, password_hash):
            logger.warning(
                f"Login failed: Invalid password for email: {form_data.username}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["email"]}, expires_delta=access_token_expires
        )

        logger.info(f"Login successful for email: {form_data.username}")
        return {"access_token": access_token, "token_type": "bearer"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error for {form_data.username}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}",
        )


@auth_router.get("/me", response_model=UserResponse)
async def get_me(current_user: UserInDB = Depends(get_current_user)):
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role,
        createdAt=datetime.utcnow(),  # You might want to store this in the DB
        updatedAt=datetime.utcnow(),
    )


# Include auth router
fastapi_app.include_router(auth_router, prefix="/api/auth", tags=["auth"])


# Additional models for video management
class VideoUpload(BaseModel):
    title: str
    description: Optional[str] = None
    genre: str
    ageRating: str = Field(..., pattern="^(G|PG|PG-13|R|18\+)$")
    fileUrl: str  # This will be provided from the blob upload
    thumbnailUrl: Optional[str] = None
    sizeMb: Optional[float] = None
    contentType: Optional[str] = None
    originalFilename: Optional[str] = None


class VideoResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    genre: str
    ageRating: str  # Changed from age_rating to match record
    uploadDate: str  # Changed from upload_date to match record
    creatorId: str  # Changed from uploader_id to match record
    viewCount: int = 0  # Changed from views to match record
    fileUrl: str  # Changed from blob_url to match record
    thumbnailUrl: Optional[str] = None
    status: Optional[str] = None
    sizeMb: Optional[float] = None
    contentType: Optional[str] = None
    originalFilename: Optional[str] = None
    average_rating: Optional[float] = None


class CommentCreate(BaseModel):
    video_id: str
    text: str


class CommentResponse(BaseModel):
    id: str
    video_id: str
    user_email: str
    text: str
    timestamp: datetime


class RatingCreate(BaseModel):
    video_id: str
    rating: int = Field(..., ge=1, le=5)


# Helper function for authentication
async def get_current_user_from_token(token: str = Depends(oauth2_scheme)):
    try:
        from jose import jwt

        payload = jwt.decode(
            token, CONFIG["JWT_SECRET_KEY"], algorithms=[CONFIG["JWT_ALGORITHM"]]
        )
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")

        users_container = cosmos_client.get_container("users")
        query = "SELECT * FROM c WHERE c.email = @email"
        parameters = [{"name": "@email", "value": email}]
        users = list(
            users_container.query_items(
                query=query, parameters=parameters, enable_cross_partition_query=True
            )
        )

        if not users:
            raise HTTPException(status_code=401, detail="User not found")

        user = users[0]
        # Add role information to the returned user object
        user["role"] = user.get("role", "CONSUMER")
        return user
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")


# Role-based authorization helper
async def require_creator_role(
    current_user: dict = Depends(get_current_user_from_token),
):
    """Dependency to ensure user has CREATOR role"""
    if current_user.get("role") != "CREATOR":
        raise HTTPException(
            status_code=403,
            detail="Access denied. Creator role required for this operation.",
        )
    return current_user


# Video endpoints
@fastapi_app.get("/api/videos", response_model=List[VideoResponse])
async def list_videos(skip: int = 0, limit: int = 10):
    """Get latest videos for dashboard"""
    try:
        videos_container = cosmos_client.get_container("videos")
        query = "SELECT * FROM c ORDER BY c.uploadDate DESC OFFSET @skip LIMIT @limit"
        params = [{"name": "@skip", "value": skip}, {"name": "@limit", "value": limit}]

        videos = list(
            videos_container.query_items(
                query=query, parameters=params, enable_cross_partition_query=True
            )
        )

        video_responses = []
        for video in videos:
            video_responses.append(
                VideoResponse(
                    id=video["id"],
                    title=video["title"],
                    description=video.get("description", ""),
                    genre=video["genre"],
                    ageRating=video["ageRating"],
                    uploadDate=video["uploadDate"],
                    creatorId=video["creatorId"],
                    viewCount=video.get("viewCount", 0),
                    fileUrl=video["fileUrl"],
                    thumbnailUrl=video.get("thumbnailUrl"),
                    status=video.get("status"),
                    sizeMb=video.get("sizeMb"),
                    contentType=video.get("contentType"),
                    originalFilename=video.get("originalFilename"),
                    average_rating=video.get("average_rating"),
                )
            )
        return video_responses
    except Exception as e:
        logger.error(f"Error listing videos: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list videos")


@fastapi_app.post("/api/upload/video", response_model=VideoResponse)
async def upload_video_file(
    video_file: UploadFile = File(...),
    thumbnail_file: Optional[UploadFile] = File(None),
    title: str = Form(...),
    description: Optional[str] = Form(None),
    genre: Optional[str] = Form(None),
    ageRating: str = Form(..., regex="^(G|PG|PG-13|R|18+)$"),
    current_user: dict = Depends(require_creator_role),
):
    """Upload video file with metadata (creators only)"""
    try:
        # Validate file type
        if not video_file.content_type.startswith("video/"):
            raise HTTPException(status_code=400, detail="File must be a video")

        # Read file data
        video_data = await video_file.read()
        file_size_mb = round(len(video_data) / (1024 * 1024), 2)

        # Upload video to blob storage
        video_blob_name, video_blob_url = upload_video_to_blob(
            video_data, video_file.filename, video_file.content_type
        )

        # Generate secure URL for video access
        secure_video_url = get_secure_blob_url(
            video_blob_name, CONFIG["AZURE_STORAGE_CONTAINER"], expiry_hours=24
        )

        # Handle thumbnail upload if provided
        thumbnail_blob_name = None
        thumbnail_url = None
        if thumbnail_file:
            thumbnail_data = await thumbnail_file.read()
            thumbnail_blob_name, thumbnail_url = upload_thumbnail_to_blob(
                thumbnail_data, thumbnail_file.filename, thumbnail_file.content_type
            )

        # Create video document
        video_id = str(uuid.uuid4())
        now = datetime.utcnow()

        video_doc = {
            "id": video_id,
            "creatorId": current_user["id"],
            "title": title,
            "description": description or "",
            "fileUrl": secure_video_url or video_blob_url,
            "thumbnailUrl": thumbnail_url,
            "genre": genre,
            "ageRating": ageRating,
            "uploadDate": now.isoformat(),
            "viewCount": 0,
            "status": "ready",
            "sizeMb": file_size_mb,
            "originalUrl": video_blob_url,
            "blobName": video_blob_name,
            "thumbnailBlobName": thumbnail_blob_name,
            "contentType": video_file.content_type,
            "originalFilename": video_file.filename,
            "average_rating": None,
        }

        # Save to database
        videos_container = cosmos_client.get_container("videos")
        created_video = videos_container.create_item(video_doc)

        log_database_operation(
            "create",
            "videos",
            {
                "video_id": video_id,
                "creator_id": current_user["id"],
                "title": title,
                "file_size_mb": file_size_mb,
                "blob_name": video_blob_name,
            },
        )

        return VideoResponse(
            id=created_video["id"],
            title=created_video["title"],
            description=created_video["description"],
            genre=created_video["genre"],
            ageRating=created_video["ageRating"],
            uploadDate=created_video["uploadDate"],
            creatorId=created_video["creatorId"],
            viewCount=created_video["viewCount"],
            fileUrl=created_video["fileUrl"],
            thumbnailUrl=created_video.get("thumbnailUrl"),
            status=created_video["status"],
            sizeMb=created_video["sizeMb"],
            contentType=created_video["contentType"],
            originalFilename=created_video["originalFilename"],
            average_rating=created_video["average_rating"],
        )

    except Exception as e:
        logger.error(f"Error uploading video: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to upload video")


# Keep the old metadata-only endpoint for backward compatibility
@fastapi_app.post("/api/videos", response_model=VideoResponse)
async def upload_video(
    video_data: VideoUpload, current_user: dict = Depends(require_creator_role)
):
    """Upload video metadata (creators only)"""
    try:
        video_id = str(uuid.uuid4())
        now = datetime.utcnow()

        video_doc = {
            "id": video_id,
            "creatorId": current_user["id"],
            "title": video_data.title,
            "description": video_data.description or "",
            "fileUrl": video_data.fileUrl,
            "thumbnailUrl": video_data.thumbnailUrl,
            "genre": video_data.genre,
            "ageRating": video_data.ageRating,
            "uploadDate": now.isoformat(),
            "viewCount": 0,
            "status": "ready",
            "sizeMb": video_data.sizeMb,
            "contentType": video_data.contentType,
            "originalFilename": video_data.originalFilename,
            "average_rating": None,
        }

        videos_container = cosmos_client.get_container("videos")
        created_video = videos_container.create_item(video_doc)

        return VideoResponse(
            id=created_video["id"],
            title=created_video["title"],
            description=created_video["description"],
            genre=created_video["genre"],
            ageRating=created_video["ageRating"],
            uploadDate=created_video["uploadDate"],
            creatorId=created_video["creatorId"],
            viewCount=created_video["viewCount"],
            fileUrl=created_video["fileUrl"],
            thumbnailUrl=created_video.get("thumbnailUrl"),
            status=created_video["status"],
            sizeMb=created_video.get("sizeMb"),
            contentType=created_video.get("contentType"),
            originalFilename=created_video.get("originalFilename"),
            average_rating=created_video["average_rating"],
        )
    except Exception as e:
        logger.error(f"Error uploading video: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to upload video")


@fastapi_app.get("/api/videos/search", response_model=List[VideoResponse])
async def search_videos(q: Optional[str] = None, genre: Optional[str] = None):
    """Search videos by title or genre"""
    try:
        videos_container = cosmos_client.get_container("videos")
        where_clauses = []
        params = []

        if q:
            where_clauses.append("CONTAINS(LOWER(c.title), LOWER(@query))")
            params.append({"name": "@query", "value": q})

        if genre:
            where_clauses.append("c.genre = @genre")
            params.append({"name": "@genre", "value": genre})

        where_clause = " AND ".join(where_clauses) if where_clauses else "1=1"
        query = f"SELECT * FROM c WHERE {where_clause} ORDER BY c.uploadDate DESC"

        videos = list(
            videos_container.query_items(
                query=query, parameters=params, enable_cross_partition_query=True
            )
        )

        video_responses = []
        for video in videos:
            video_responses.append(
                VideoResponse(
                    id=video["id"],
                    title=video["title"],
                    description=video.get("description", ""),
                    genre=video["genre"],
                    ageRating=video["ageRating"],
                    uploadDate=video["uploadDate"],
                    creatorId=video["creatorId"],
                    viewCount=video.get("viewCount", 0),
                    fileUrl=video["fileUrl"],
                    thumbnailUrl=video.get("thumbnailUrl"),
                    status=video.get("status"),
                    sizeMb=video.get("sizeMb"),
                    contentType=video.get("contentType"),
                    originalFilename=video.get("originalFilename"),
                    average_rating=video.get("average_rating"),
                )
            )
        return video_responses
    except Exception as e:
        logger.error(f"Error searching videos: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to search videos")


@fastapi_app.get("/api/videos/{video_id}", response_model=VideoResponse)
async def get_video(video_id: str):
    """Get specific video and increment view count"""
    try:
        videos_container = cosmos_client.get_container("videos")

        # First try to read the video by ID (since videos are partitioned by /id)
        try:
            video = videos_container.read_item(item=video_id, partition_key=video_id)
        except exceptions.CosmosResourceNotFoundError:
            # If direct read fails, try querying (for cross-partition query)
            query = "SELECT * FROM c WHERE c.id = @video_id"
            params = [{"name": "@video_id", "value": video_id}]
            videos = list(
                videos_container.query_items(
                    query=query, parameters=params, enable_cross_partition_query=True
                )
            )
            if not videos:
                raise HTTPException(status_code=404, detail="Video not found")
            video = videos[0]

        # Increment view count
        video["viewCount"] = video.get("viewCount", 0) + 1
        # Replace the item (partition key is automatically inferred from the document)
        videos_container.replace_item(item=video_id, body=video)

        return VideoResponse(
            id=video["id"],
            title=video["title"],
            description=video.get("description", ""),
            genre=video["genre"],
            ageRating=video["ageRating"],
            uploadDate=video["uploadDate"],
            creatorId=video["creatorId"],
            viewCount=video["viewCount"],
            fileUrl=video["fileUrl"],
            thumbnailUrl=video.get("thumbnailUrl"),
            status=video.get("status"),
            sizeMb=video.get("sizeMb"),
            contentType=video.get("contentType"),
            originalFilename=video.get("originalFilename"),
            average_rating=video.get("average_rating"),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting video {video_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get video")


@fastapi_app.post("/api/comments", response_model=CommentResponse)
async def add_comment(
    comment_data: CommentCreate,
    current_user: dict = Depends(get_current_user_from_token),
):
    """Add comment to video"""
    try:
        comment_id = str(uuid.uuid4())
        now = datetime.utcnow()

        comment_doc = {
            "id": comment_id,
            "video_id": comment_data.video_id,
            "user_email": current_user["email"],
            "text": comment_data.text,
            "timestamp": now.isoformat(),
        }

        # Use the cosmos_client instance and ensure container exists
        comments_container = cosmos_client.get_container("comments")
        created_comment = comments_container.create_item(comment_doc)

        return CommentResponse(
            id=created_comment["id"],
            video_id=created_comment["video_id"],
            user_email=created_comment["user_email"],
            text=created_comment["text"],
            timestamp=datetime.fromisoformat(created_comment["timestamp"]),
        )
    except Exception as e:
        logger.error(f"Error adding comment: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to add comment")


@fastapi_app.get(
    "/api/videos/{video_id}/comments", response_model=List[CommentResponse]
)
async def get_video_comments(video_id: str):
    """Get comments for a video"""
    try:
        comments_container = cosmos_client.get_container("comments")
        query = "SELECT * FROM c WHERE c.video_id = @video_id ORDER BY c.timestamp DESC"
        params = [{"name": "@video_id", "value": video_id}]

        comments = list(
            comments_container.query_items(
                query=query, parameters=params, enable_cross_partition_query=True
            )
        )

        comment_responses = []
        for comment in comments:
            comment_responses.append(
                CommentResponse(
                    id=comment["id"],
                    video_id=comment["video_id"],
                    user_email=comment["user_email"],
                    text=comment["text"],
                    timestamp=datetime.fromisoformat(comment["timestamp"]),
                )
            )
        return comment_responses
    except Exception as e:
        logger.error(f"Error getting comments: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get comments")


@fastapi_app.post("/api/ratings")
async def rate_video(
    rating_data: RatingCreate, current_user: dict = Depends(get_current_user_from_token)
):
    """Rate a video (1-5 stars)"""
    try:
        # Check if user already rated this video
        ratings_container = cosmos_client.get_container("ratings")
        query = "SELECT * FROM c WHERE c.video_id = @video_id AND c.user_email = @user_email"
        params = [
            {"name": "@video_id", "value": rating_data.video_id},
            {"name": "@user_email", "value": current_user["email"]},
        ]
        existing_ratings = list(
            ratings_container.query_items(
                query=query, parameters=params, enable_cross_partition_query=True
            )
        )

        if existing_ratings:
            raise HTTPException(
                status_code=400, detail="You have already rated this video"
            )

        rating_id = str(uuid.uuid4())
        rating_doc = {
            "id": rating_id,
            "video_id": rating_data.video_id,
            "user_email": current_user["email"],
            "rating": rating_data.rating,
        }

        ratings_container.create_item(rating_doc)

        # Recalculate average rating for the video
        all_ratings_query = "SELECT c.rating FROM c WHERE c.video_id = @video_id"
        all_ratings_params = [{"name": "@video_id", "value": rating_data.video_id}]
        all_ratings = list(
            ratings_container.query_items(
                query=all_ratings_query,
                parameters=all_ratings_params,
                enable_cross_partition_query=True,
            )
        )
        ratings_list = [r["rating"] for r in all_ratings if "rating" in r]
        avg_rating = (
            round(sum(ratings_list) / len(ratings_list), 2) if ratings_list else None
        )

        # Update the video's average_rating field
        videos_container = cosmos_client.get_container("videos")
        try:
            video = videos_container.read_item(
                item=rating_data.video_id, partition_key=rating_data.video_id
            )
        except exceptions.CosmosResourceNotFoundError:
            # If direct read fails, try querying (for cross-partition query)
            video_query = "SELECT * FROM c WHERE c.id = @video_id"
            video_params = [{"name": "@video_id", "value": rating_data.video_id}]
            videos = list(
                videos_container.query_items(
                    query=video_query,
                    parameters=video_params,
                    enable_cross_partition_query=True,
                )
            )
            if not videos:
                raise HTTPException(
                    status_code=404, detail="Video not found for rating update"
                )
            video = videos[0]

        video["average_rating"] = avg_rating
        videos_container.replace_item(item=video["id"], body=video)

        return {"message": "Rating added successfully", "average_rating": avg_rating}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rating video: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to rate video")


@fastapi_app.post("/api/test/containers")
async def test_containers():
    """Test endpoint to initialize and verify all containers"""
    try:
        db_client = CosmosDBClient()

        # Verify each container exists
        containers_status = {}
        for container_name in ["users", "videos", "comments", "ratings"]:
            try:
                container = db_client.get_container(container_name)
                containers_status[container_name] = "EXISTS"
            except Exception as e:
                containers_status[container_name] = f"ERROR: {str(e)}"

        return {
            "message": "Container initialization test completed",
            "containers": containers_status,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.error(f"Container test failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Container test failed: {str(e)}")


@fastapi_app.get("/api/test/videos")
async def test_videos():
    """Test endpoint to list first few videos and check partition keys"""
    try:
        videos_container = cosmos_client.get_container("videos")

        # Get first 3 videos to inspect structure
        query = "SELECT TOP 3 * FROM c"
        videos = list(
            videos_container.query_items(query=query, enable_cross_partition_query=True)
        )

        return {
            "message": "Video test completed",
            "video_count": len(videos),
            "videos": videos,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.error(f"Video test failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Video test failed: {str(e)}")


@fastapi_app.post("/api/admin/create-creator", response_model=UserResponse)
async def create_creator_user(user_data: UserCreate):
    """Admin endpoint to create a CREATOR user (no authentication required for simplicity)"""
    if not cosmos_client:
        raise HTTPException(status_code=500, detail="Database connection failed")

    users_container = cosmos_client.get_container("users")
    logger.info(f"Creating CREATOR account for email: {user_data.email}")

    try:
        # Check if user already exists
        query = "SELECT * FROM c WHERE c.email = @email"
        parameters = [{"name": "@email", "value": user_data.email}]
        existing_users = list(
            users_container.query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True,
            )
        )

        if existing_users:
            logger.warning(
                f"Creator creation failed: Email already exists: {user_data.email}"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        # Create new CREATOR user
        hashed_password = get_password_hash(user_data.password)
        user_id = str(uuid.uuid4())
        now = datetime.utcnow()

        user_doc = {
            "id": user_id,
            "email": user_data.email,
            "passwordHash": hashed_password,
            "role": "CREATOR",  # This endpoint creates creators
            "disabled": False,
            "createdAt": now.isoformat(),
            "updatedAt": now.isoformat(),
        }

        created_user = users_container.create_item(user_doc)
        logger.info(
            f"CREATOR user created: {created_user['email']} (id: {created_user['id']})"
        )

        return UserResponse(
            id=created_user["id"],
            email=created_user["email"],
            role=created_user["role"],
            createdAt=datetime.fromisoformat(created_user["createdAt"]),
            updatedAt=datetime.fromisoformat(created_user["updatedAt"]),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Creator creation error for {user_data.email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Creator creation failed: {str(e)}",
        )


# Azure Functions App
app = FunctionApp(http_auth_level=AuthLevel.ANONYMOUS)


@app.function_name(name="HttpTrigger")
@app.route(
    route="{*route}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
)
async def main(req: HttpRequest) -> HttpResponse:
    """Main HTTP trigger function that routes all requests to FastAPI"""
    try:
        # Import AsgiMiddleware here to avoid import issues
        from azure.functions import AsgiMiddleware

        return await AsgiMiddleware(fastapi_app).handle_async(req, None)
    except Exception as e:
        logger.error(f"Error in main function: {str(e)}")
        return HttpResponse(
            f"Internal server error: {str(e)}",
            status_code=500,
            headers={"Content-Type": "text/plain"},
        )
