import os
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import jsonify, session
from datetime import datetime
import re

# Robust log level resolution
def _resolve_log_level(level_name: str | None) -> int:
    if not level_name:
        return logging.INFO
    try:
        return getattr(logging, level_name.upper())
    except Exception:
        return logging.INFO

LOG_LEVEL = _resolve_log_level(os.getenv("LOG_LEVEL", "INFO"))
LOG_FILE = os.getenv("LOG_FILE")  # do NOT default to a file

# Configure logging: prefer console (stdout/stderr) for serverless environments.
# If LOG_FILE is explicitly set and writable, use a FileHandler as well.
handlers = [logging.StreamHandler()]

if LOG_FILE:
    # Allow local development to log to a file if explicitly configured.
    try:
        # Use FileHandler only if the path is writable
        fh = logging.FileHandler(LOG_FILE)
        handlers.insert(0, fh)
    except Exception:
        # Fall back to console if file can't be opened
        pass

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=handlers,
)

logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    """Hash a password using Werkzeug's security functions."""
    return generate_password_hash(password)

def verify_password(password_hash: str, password: str) -> bool:
    """Verify a password against its hash."""
    return check_password_hash(password_hash, password)

def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))

def validate_phone(phone: str) -> bool:
    """Validate phone number format (E.164-like)."""
    pattern = r"^\+?1?\d{9,15}$"
    return bool(re.match(pattern, phone))

def validate_coordinates(latitude, longitude) -> bool:
    """Validate geographical coordinates."""
    try:
        lat = float(latitude)
        lon = float(longitude)
        return -90 <= lat <= 90 and -180 <= lon <= 180
    except (ValueError, TypeError):
        return False

def admin_required(f):
    """Decorator to require admin authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin" not in session:
            logger.warning("Unauthorized admin access attempt")
            return jsonify({"error": "Admin authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

def user_required(f):
    """Decorator to require user authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            logger.warning("Unauthorized user access attempt")
            return jsonify({"error": "User authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

def log_error(error: Exception, context: str | None = None) -> None:
    """Log an error with context."""
    error_message = f"Error: {str(error)}"
    if context:
        error_message += f" Context: {context}"
    logger.error(error_message)

def format_datetime(dt) -> str | None:
    """Format datetime object to string."""
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return None

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent security issues."""
    # Remove any path traversal attempts
    filename = os.path.basename(filename)
    # Remove any non-alphanumeric characters except dots and hyphens
    filename = re.sub(r"[^a-zA-Z0-9.-]", "_", filename)
    # Prevent filenames that start with a dot (hidden files)
    if filename.startswith("."):
        filename = "_" + filename.lstrip(".")
    return filename
