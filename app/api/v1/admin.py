from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from supabase import AuthApiError, Client, ClientOptions, create_client

from ...utils.utils import json_serialize, settings_dependency

router = APIRouter()


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
                    "secondName": user["user_metadata"].get(
                        "lastName", ""
                    ),  # Safely get lastName or empty string
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
    # Maybve user the Admin Auth client, this will allow to use to the email confirm option
    # Get data
    data = await request.json()
    firstName = data.get("firstName")
    lastName = data.get("lastName")
    email = data.get("email")
    phoneNumber = data.get("phoneNumber")
    password = data.get("password")
    autoConfirm = True if data.get("autoConfirm") == "true" else False

    # Print the data for debugging
    print(f"User Data:")
    print(
        f"First Name: {firstName}\nLast Name: {lastName}\nEmail: {email}\nPhone: {phoneNumber}\nPassword: {password}\nAuto Confirm: {autoConfirm}"
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
