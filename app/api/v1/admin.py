from fastapi import APIRouter

router = APIRouter()


# just to get an idea of what works
@router.get("/")
def health_check():
    return {"status": "healthy"}
