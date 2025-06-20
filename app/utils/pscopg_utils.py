from functools import lru_cache
from fastapi import Depends
import psycopg
from typing import Annotated, Any, List, Optional, Tuple
from ..core.config import Settings
from ..utils.core_utils import settings_dependency

# @lru_cache
# def get_settings():
#     return Settings()


# settings_dependency = Annotated[Settings, Depends(get_settings)]
db_url = settings_dependency().SUPABASE_DB_URL


def fetch_one(query: str, params: Optional[Tuple] = None) -> Optional[dict]:
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            row = cur.fetchone()
            if row:
                columns = [desc[0] for desc in cur.description]
                return dict(zip(columns, row))
            return None


def fetch_all(query: str, params: Optional[Tuple] = None) -> list:
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, row)) for row in rows]


def execute_query(query: str, params: Optional[Tuple] = None) -> int:
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            affected = cur.rowcount
            conn.commit()
            return affected


def execute_returning(query: str, params: Optional[Tuple] = None) -> Optional[dict]:
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            row = cur.fetchone()
            if row:
                columns = [desc[0] for desc in cur.description]
                return dict(zip(columns, row))
            return None
