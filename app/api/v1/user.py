from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from supabase import Client, ClientOptions, create_client
from datetime import datetime, timezone

from ...utils.utils import settings_dependency

router = APIRouter()


@router.get("/")
async def health_check():
    return "Reached User Endpoint, Router User is Active"


@router.post("/tickets")
async def create_ticket(request: Request, settings: settings_dependency):
    data = await request.json()
    title = data.get("title")
    description = data.get("description")
    user_id = data.get("user_id")  # Accept UUID as string

    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_ANON_KEY,
    )

    try:
        print(f"Attempting to submit ticket: {title}")
        print(f"User ID (UUID): {user_id}")
        print(f"Description: {description}")
        
        response = supabase.table('tickets').insert({
            'title': title,
            'description': description,
            'user_id': user_id,  # Use UUID directly
            'status': 'pending'
            # Let the database handle created_at and updated_at defaults
        }).execute()

        print(f"Response: {response}")
        return JSONResponse(content=response.data, status_code=200)
    except Exception as e:
        print(f"Error creating ticket: {str(e)}")  # Add error logging
        return JSONResponse(content={"error": str(e)}, status_code=500)
