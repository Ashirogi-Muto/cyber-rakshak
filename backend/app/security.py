# backend/app/security.py

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import HTTPException, status, Depends
from typing import Optional
import os
from .auth import get_current_user
from .models import User

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Scan profiles with their rate limits
SCAN_PROFILE_LIMITS = {
    "safe": "5/minute",      # 5 scans per minute
    "normal": "3/minute",    # 3 scans per minute
    "deep": "1/5minute"      # 1 scan per 5 minutes (requires admin)
}

# Deep scan consent requirements
DEEP_SCAN_CONSENT_REQUIRED = True

# Authorized targets (in a real application, this would be in a database)
AUTHORIZED_TARGETS = {
    "admin": ["*"],  # Admins can scan any target
    "user": ["scanme.nmap.org", "127.0.0.1", "localhost"]  # Regular users have limited targets
}

def get_scan_limit(profile: str, user: User) -> str:
    """
    Get the rate limit for a scan profile.
    
    Args:
        profile: Scan profile (safe, normal, deep)
        user: Current user
        
    Returns:
        Rate limit string
        
    Raises:
        HTTPException: If user is not authorized for deep scans
    """
    if profile == "deep" and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Deep scans require admin privileges"
        )
    
    return SCAN_PROFILE_LIMITS.get(profile, "5/minute")


def verify_scan_authorization(target: str, profile: str, user: User) -> bool:
    """
    Verify that the user is authorized to scan the target with the given profile.
    
    Args:
        target: Target to scan
        profile: Scan profile
        user: Current user
        
    Returns:
        True if authorized, False otherwise
        
    Raises:
        HTTPException: If user is not authorized
    """
    # Check if deep scan requires consent
    if profile == "deep" and DEEP_SCAN_CONSENT_REQUIRED:
        # In a real implementation, check if user has given consent for this target
        # For demonstration, we'll allow it for admin users
        if user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Deep scans require admin privileges and explicit consent"
            )
        return True
    
    # Check if user is authorized to scan this target
    authorized_targets = AUTHORIZED_TARGETS.get(user.role, [])
    if "*" not in authorized_targets and target not in authorized_targets:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"You are not authorized to scan {target}"
        )
    
    # For safe and normal scans, basic authorization is sufficient
    return True


def validate_target(target: str) -> bool:
    """
    Validate that the target is acceptable for scanning.
    
    Args:
        target: Target to validate
        
    Returns:
        True if valid, False otherwise
    """
    # Basic validation - in a real application, implement more thorough validation
    # to prevent scanning of unauthorized targets
    
    # Check if target is empty
    if not target:
        return False
    
    # Check if target contains potentially dangerous characters
    # This is a simplified check - implement more robust validation in production
    forbidden_chars = [";", "|", "&", "`", "$", "(", ")", "{", "}", "[", "]"]
    for char in forbidden_chars:
        if char in target:
            return False
    
    # Check if target is a valid IP address or domain name
    import re
    # Simple regex for IP validation
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # Simple regex for domain validation
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(ip_pattern, target) and not re.match(domain_pattern, target) and target not in ["localhost", "127.0.0.1"]:
        return False
    
    return True


def create_audit_log_entry(user_id: str, action: str, target: str, details: Optional[dict] = None):
    """
    Create an audit log entry for a security-sensitive action.
    
    Args:
        user_id: ID of the user performing the action
        action: Action performed
        target: Target of the action
        details: Additional details about the action
    """
    # In a real implementation, this would write to the audit log database
    # For demonstration, we'll just print to console
    import datetime
    timestamp = datetime.datetime.now().isoformat()
    print(f"AUDIT LOG [{timestamp}]: User {user_id} performed {action} on {target}")
    if details:
        print(f"  Details: {details}")


def check_consent(user_id: str, target: str) -> bool:
    """
    Check if user has given consent for scanning the target.
    
    Args:
        user_id: ID of the user
        target: Target to scan
        
    Returns:
        True if consent is given, False otherwise
    """
    # In a real implementation, this would check a consent database
    # For demonstration, we'll return True for authorized targets
    return True