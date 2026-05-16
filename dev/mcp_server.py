#!/usr/bin/env python3
"""MCP server for the gate dev PostgreSQL container.

Exposes three tools:
  list_tables      — all tables in the public schema
  describe_table   — column names + types for a given table
  execute_query    — run a SELECT and return rows as JSON-safe dicts

Connection defaults match dev/docker-compose.yml.
Override via env: PG_HOST PG_PORT PG_DB PG_USER PG_PASS
"""

import datetime
import decimal
import json
import os

import psycopg2
import psycopg2.extras
from mcp.server.fastmcp import FastMCP

PG_HOST = os.environ.get("PG_HOST", "localhost")
PG_PORT = int(os.environ.get("PG_PORT", "5432"))
PG_DB   = os.environ.get("PG_DB",   "gatepay")
PG_USER = os.environ.get("PG_USER", "gate")
PG_PASS = os.environ.get("PG_PASS", "gate")

mcp = FastMCP("postgres-local-demo")


def _connect():
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT,
        dbname=PG_DB, user=PG_USER, password=PG_PASS,
    )


def _json_safe(rows: list[dict]) -> list[dict]:
    """Convert psycopg2 native types (datetime, Decimal) to JSON-native equivalents."""
    def coerce(v):
        if isinstance(v, (datetime.date, datetime.datetime)):
            return v.isoformat()
        if isinstance(v, decimal.Decimal):
            return float(v)
        return v
    return [{k: coerce(v) for k, v in row.items()} for row in rows]


@mcp.tool()
def list_tables() -> list[str]:
    """Return the names of all user tables in the public schema."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT tablename FROM pg_tables"
            " WHERE schemaname = 'public' ORDER BY tablename"
        )
        return [row[0] for row in cur.fetchall()]


@mcp.tool()
def describe_table(table: str) -> list[dict]:
    """Return column name, data_type, is_nullable, and column_default for each column."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s
            ORDER BY ordinal_position
            """,
            (table,),
        )
        col_names = [desc[0] for desc in cur.description]
        return [dict(zip(col_names, row)) for row in cur.fetchall()]


@mcp.tool()
def execute_query(sql: str) -> list[dict]:
    """Execute a SQL SELECT query and return rows as a list of JSON-safe dicts.

    Only SELECT statements are permitted. Use list_tables / describe_table
    to explore the schema before querying.
    """
    if not sql.strip().upper().startswith("SELECT"):
        raise ValueError("Only SELECT queries are permitted")
    with _connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql)
        return _json_safe([dict(row) for row in cur.fetchall()])


if __name__ == "__main__":
    mcp.run()
