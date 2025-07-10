"""
Common API utilities and middleware.
"""

from typing import Any, Dict, Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


async def parse_json_body(request: Request) -> Dict[str, Any]:
    """Parse JSON body with error handling."""
    try:
        return await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON format")


def create_error_response(message: str, status_code: int = 500) -> JSONResponse:
    """Create standardized error response."""
    return JSONResponse(
        content={"error": message, "authenticated": False}, status_code=status_code
    )


def create_success_response(
    message: str, data: Optional[Dict[str, Any]] = None, status_code: int = 200
) -> JSONResponse:
    """Create standardized success response."""
    content = {"message": message, "authenticated": True}
    if data:
        content.update(data)
    return JSONResponse(content=content, status_code=status_code)


def validate_required_fields(
    data: Dict[str, Any], required_fields: list
) -> Optional[str]:
    """Validate that required fields are present in data."""
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return f"Missing required fields: {', '.join(missing_fields)}"
    return None
