from fastapi import APIRouter

router = APIRouter()


@router.get("/")
async def health_check():
    return "Reached Auth Endpoint, Router Auth is Active"
