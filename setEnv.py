"""
Basic script to set environment variables for Supabase URL and Key.
NOTE:: For production, its best to use a key manager of some sort and not store the key in the code.

Run this script before running the FastAPI app to set the environment variables.
"""

import os

os.environ["SUPABASE_URL"] = "http://localhost:54321"
os.environ["SUPABASE_KEY"] = (

print("ENV vars set!")
print("Fetching ENV vars...")
print(f"SUPABASE_URL: {os.getenv('SUPABASE_URL')}")
print(f"SUPABASE_KEY: {os.getenv('SUPABASE_KEY')}")
