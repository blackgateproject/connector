from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from supabase import Client, create_client

from ...utils.utils import settings_dependency

router = APIRouter()

@router.post("/log")
async def log_action(request: Request, settings: settings_dependency):
    data = await request.json()
    user_id = data.get("user_id")
    activity = data.get("activity")

    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_SERV_KEY,
    )

    try:
        response = supabase.table("user_activity_logs").insert(
            {
                "user_id": user_id,
                "activity": activity,
            }
        ).execute()
        return JSONResponse(content={"message": "Log created successfully"}, status_code=200)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
