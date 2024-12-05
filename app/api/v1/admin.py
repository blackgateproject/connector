from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from supabase import AuthApiError, Client, ClientOptions, create_client

from ...utils.utils import json_serialize, log_user_action, settings_dependency

router = APIRouter()


@router.get("/user-activity-logs")
async def get_user_activity_logs(settings: settings_dependency):
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_SERV_KEY,
    )

    try:
        response = supabase.table("user_activity_logs").select("*").execute()
        return JSONResponse(content=response.data, status_code=200)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


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
        response = (
            supabase.table("user_activity_logs")
            .insert(
                {
                    "user_id": user_id,
                    "activity": activity,
                    "type": data.get("type"),  # Include type in the log
                }
            )
            .execute()
        )
        return JSONResponse(
            content={"message": "Log created successfully"}, status_code=200
        )
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/")
async def health_check():
    return "Reached Admin Endpoint, Router Admin is Active"


@router.get("/getUsers")
async def getUsers(settings: settings_dependency):
    # Initialize the Supabase client
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_SERV_KEY,
        options=ClientOptions(auto_refresh_token=False, persist_session=False),
    )

    try:
        # Fetch users from Supabase (admin API for listing users)
        users_response = supabase.auth.admin.list_users(page=1, per_page=100)

        # Check the structure of the response (print it for inspection)
        print(f"Users Response: {users_response}")

        # The response might be a list of User objects. We need to serialize them.
        users = users_response  # The response is a list of User objects

        # Serialize user data to JSON-friendly format
        serialized_users = []
        for user in users:
            serialized_user = {
                "id": user.id,
                "app_metadata": json_serialize(user.app_metadata),
                "user_metadata": json_serialize(user.user_metadata),
                "aud": user.aud,
                "confirmation_sent_at": json_serialize(user.confirmation_sent_at),
                "recovery_sent_at": json_serialize(user.recovery_sent_at),
                "email_change_sent_at": json_serialize(user.email_change_sent_at),
                "new_email": user.new_email,
                "new_phone": user.new_phone,
                "invited_at": json_serialize(user.invited_at),
                "action_link": user.action_link,
                "email": user.email,
                "phone": user.phone,
                "created_at": json_serialize(user.created_at),
                "confirmed_at": json_serialize(user.confirmed_at),
                "email_confirmed_at": json_serialize(user.email_confirmed_at),
                "phone_confirmed_at": json_serialize(user.phone_confirmed_at),
                "last_sign_in_at": json_serialize(user.last_sign_in_at),
                "role": user.role,
                "updated_at": json_serialize(user.updated_at),
                "identities": json_serialize(user.identities),
                "is_anonymous": user.is_anonymous,
                "factors": json_serialize(user.factors),
            }
            serialized_users.append(serialized_user)

        # Print the serialized user data
        print(f"Serialized Users: {serialized_users}")

        # Initialize the list to hold the return users
        returnUsers = []

        # Loop through serialized users
        for user in serialized_users:
            # Fetch the role from the user_roles table
            role = " "
            role_response = (
                supabase.table("user_roles")
                .select("role")
                .eq("user_id", user["id"])
                .single()
                .execute()
            )
            role = role_response.data["role"] if role_response.data else "user"

            # Print User id for debugging
            print(f"User ID: {user['id']}")

            if user["user_metadata"] == {}:  # Check if user_metadata is empty
                print(f"No User Metadata for {user['id']}")
                last_sign_in_at = datetime.fromisoformat(
                    user["last_sign_in_at"]
                )  # Convert last_sign_in_at to datetime object
                print(f"Last Sign In At: {last_sign_in_at}")
                print(f"Time Now: {datetime.now(timezone.utc)}")
                print(f"Time Diff: {last_sign_in_at - datetime.now(timezone.utc)}")
                returnUser = {
                    "id": user["id"],
                    "firstName": user[
                        "email"
                    ],  # Using email as first name for users without metadata
                    "secondName": "",  # No second name if no metadata
                    "email": user["email"],
                    "role": role if role else "N/A",
                    # Set online to true if last_sign_in_at was 5 mins ago. time is stored as 2024-12-01T20:53:27.176864+00:00
                    "online": (
                        True
                        if last_sign_in_at
                        > datetime.now(timezone.utc) - timedelta(minutes=5)
                        else False
                    ),  # Check if the user is authenticated
                }
                # Append the return user to the list
                returnUsers.append(returnUser)
                print(f"Return USR: \n{returnUser}")
            else:
                # User has metadata, so extract first and last names
                returnUser = {
                    "id": user["id"],
                    "firstName": user["user_metadata"].get(
                        "firstName", ""
                    ),  # Safely get firstName or empty string
                    "lastName": user["user_metadata"].get(
                        "lastName", ""
                    ),  # Safely get lastName or empty string
                    "email": user["email"],
                    "role": role,
                    "online": (
                        True if user["aud"] == "authenticated" else False
                    ),  # Check if the user is authenticated
                }

                # Append the return user to the list
                returnUsers.append(returnUser)
                print(f"Return USR: \n{returnUser}")

        # Debug print the return users list
        print(f"Return OBJ: \n{returnUsers}")

        # Return the JSON response with the serialized user data
        return JSONResponse(
            content=returnUsers,
            status_code=200,
        )
    except Exception as e:
        print(f"General Error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)
    except AuthApiError as e:
        print(f"Auth Error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=401)


@router.post("/addUser")
async def addUsers(request: Request, settings: settings_dependency):
    # Get data
    data = await request.json()
    firstName = data.get("firstName")
    lastName = data.get("lastName")
    email = data.get("email")
    phoneNumber = data.get("phoneNumber")
    password = data.get("password")
    role = data.get("role")  # Get the role from the request body
    autoConfirm = True if data.get("autoConfirm") == "true" else False

    # Print the data for debugging
    print(f"User Data:")
    print(
        f"First Name: {firstName}\nLast Name: {lastName}\nEmail: {email}\nPhone: {phoneNumber}\nPassword: {password}\nRole: {role}\nAuto Confirm: {autoConfirm}"
    )

    # Initialize the Supabase client
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )

    try:
        # Add users to Supabase
        user = supabase.auth.sign_up(
            {
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "firstName": firstName,
                        "lastName": lastName,
                        "phoneNumber": phoneNumber,
                    }
                },
            }
        )
        print(f"User: {user}")

        # Map the user to their role
        user_id = user.user.id
        supabase.table("user_roles").insert(
            {"user_id": user_id, "role": role}
        ).execute()
        await log_user_action(user_id, f"Added user: {email}", settings, type="User Addition")
    except AuthApiError as e:
        return JSONResponse(content={"error": str(e)}, status_code=401)


@router.post("/getCurrentUser")
async def getCurrentUser(request: Request, settings: settings_dependency):
    # Get data
    data = await request.json()
    token = data.get("token")

    # Initialize the Supabase client
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )

    try:
        # Get the current user
        user = supabase.auth.api.get_user_by_access_token(token)
        print(f"User: {user}")
    except AuthApiError as e:
        return JSONResponse(content={"error": str(e)}, status_code=401)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/tickets")
async def get_tickets(settings: settings_dependency):
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_ANON_KEY,
    )

    try:
        response = supabase.table("tickets").select("*").execute()
        print(f"Tickets: {response.data}")
        return JSONResponse(content=response.data, status_code=200)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.post("/tickets/{ticket_id}/complete")
async def complete_ticket(ticket_id: int, settings: settings_dependency):
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_SERV_KEY,
        options=ClientOptions(auto_refresh_token=False, persist_session=False),
    )

    try:
        response = (
            supabase.table("tickets")
            .update(
                {
                    "status": "completed",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            .eq("id", ticket_id)
            .execute()
        )
        await log_user_action(ticket_id, "Completed ticket", settings, type="Ticket Completion")
        return JSONResponse(content=response.data, status_code=200)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.delete("/deleteUser/{user_id}")
async def delete_user(user_id: str, settings: settings_dependency):
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_SERV_KEY,
        options=ClientOptions(auto_refresh_token=False, persist_session=False),
    )

    try:
        response = supabase.auth.admin.delete_user(user_id)
        await log_user_action(user_id, "Deleted user", settings, type="User Deletion")
        return JSONResponse(
            content={"message": "User deleted successfully"}, status_code=200
        )
    except AuthApiError as e:
        return JSONResponse(content={"error": str(e)}, status_code=401)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.put("/editUser")
async def edit_user(request: Request, settings: settings_dependency):
    data = await request.json()
    user_id = data.get("id")
    first_name = data.get("firstName")
    last_name = data.get("lastName")
    email = data.get("email")
    phone_number = data.get("phone")
    password = data.get("password")
    role = data.get("role")

    print(f"User Data: {data}")

    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_SERV_KEY,
        options=ClientOptions(auto_refresh_token=False, persist_session=False),
    )

    try:
        response = supabase.auth.admin.update_user_by_id(
            user_id,
            {
                "email": email,
                "password": password,
                "phoneNumber": phone_number,
                "user_metadata": {
                    "firstName": first_name,
                    "lastName": last_name,
                },
            },
        )
        print(f"Response: {response}")

        # Update the user's role
        supabase.table("user_roles").upsert(
            {"user_id": user_id, "role": role}
        ).execute()
        await log_user_action(user_id, "Edited user", settings, type="User Edit")

        # Check if the response contains the requested changes
        user = response.user
        if (
            user.email == email
            and user.user_metadata.get("firstName") == first_name
            and user.user_metadata.get("lastName") == last_name
            and user.user_metadata.get("phoneNumber") == phone_number
        ):
            return JSONResponse(content={"message": "ok"}, status_code=200)
        else:
            return JSONResponse(content={"error": "Update failed"}, status_code=500)
    except AuthApiError as e:
        print(f"Error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=401)
    except Exception as e:
        print(f"Error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/profile")
async def get_admin_profile(request: Request, settings: settings_dependency):
    access_token = request.headers.get("Authorization").split(" ")[1]
    print(f"Access Token: {access_token}")
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_ANON_KEY,
    )

    try:
        user_response = supabase.auth.get_user(access_token)
        user = user_response.user
        print(f"GOT USER: {user}")

        # Fetch the role from the user_roles table
        role_response = (
            supabase.table("user_roles")
            .select("role")
            .eq("user_id", user.id)
            .single()
            .execute()
        )
        role = role_response.data["role"] if role_response.data else "admin"

        user_data = {
            "firstName": user.user_metadata.get("firstName", ""),
            "lastName": user.user_metadata.get("lastName", ""),
            "email": user.email,
            "phone": user.phone if user.phone else "N/A",
            "role": role,
        }
        await log_user_action(user.id, "Viewed admin profile", settings, type="Profile View")
        return JSONResponse(content=user_data, status_code=200)
    except Exception as e:
        print(f"Error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/getUser/{user_id}")
async def get_user(user_id: str, settings: settings_dependency):
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_SERV_KEY,
    )

    try:
        user_response = supabase.auth.admin.get_user_by_id(user_id)
        user = user_response.user

        user_data = {
            "id": user.id,
            "email": user.email,
            "firstName": user.user_metadata.get("firstName", ""),
            "lastName": user.user_metadata.get("lastName", ""),
            "phone": user.phone,
            "role": user.app_metadata.get("role", "user"),
        }

        return JSONResponse(content=user_data, status_code=200)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/getAllUsers")
async def get_all_users(settings: settings_dependency):
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_SERV_KEY,
    )

    try:
        users_response = supabase.auth.admin.list_users(page=1, per_page=100)
        users = users_response

        user_data_list = [
            {
                "id": user.id,
                "email": user.email,
                "firstName": user.user_metadata.get("firstName", ""),
                "lastName": user.user_metadata.get("lastName", ""),
                "phone": user.phone,
                "role": user.app_metadata.get("role", "user"),
            }
            for user in users
        ]

        return JSONResponse(content=user_data_list, status_code=200)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
