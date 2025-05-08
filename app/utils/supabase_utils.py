"""
This is meant to replace the supabase client with predefined postgres queries.
"""

from functools import lru_cache
from typing import Annotated, Any, List, Optional, Tuple

import psycopg
from fastapi import Depends

from ..core.config import Settings
from .core_utils import settings_dependency


@lru_cache
def get_settings():
    return Settings()


settings_dependency = Annotated[Settings, Depends(get_settings)]
db_url = settings_dependency().SUPABASE_DB_URL


def _execute_query(
    query: str, params: Optional[Tuple] = None, fetch: bool = False
) -> Any:
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            if fetch:
                return cur.fetchall()
            affected = cur.rowcount
            conn.commit()
            return affected


# Run a select query
async def run_select_query(
    query: str,
    params: Optional[Tuple] = None,
) -> List[Tuple]:
    return _execute_query(query, params, fetch=True)


# Run an update query
async def run_update_query(
    query: str,
    params: Optional[Tuple] = None,
) -> int:
    return _execute_query(query, params)


# Run a delete query
async def run_delete_query(
    query: str,
    params: Optional[Tuple] = None,
) -> int:
    return _execute_query(query, params)


# Run an upsert query
async def run_upsert_query(
    query: str,
    params: Optional[Tuple] = None,
) -> int:
    return _execute_query(query, params)
