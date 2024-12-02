from fastapi import APIRouter

router = APIRouter()


@router.get("/")
async def get_user():
    return "Reached User Endpoint, Router User is Active"
