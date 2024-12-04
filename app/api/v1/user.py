from fastapi import APIRouter

router = APIRouter()


@router.get("/")
async def health_check():
    return "Reached User Endpoint, Router User is Active"
