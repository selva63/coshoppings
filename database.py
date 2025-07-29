# database.py

# This file is primarily for defining the schema.
# The init_db function in app.py will read from a temporary schema.sql
# generated if the database doesn't exist.
# For a more robust application, you would typically run this script once
# to set up your database.

# SQL to create the products table
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    image_url TEXT
);
"""

# You can run this file directly to initialize the database outside of Flask context if needed
# import sqlite3
# DATABASE = 'database.db'
# conn = sqlite3.connect(DATABASE)
# cursor = conn.cursor()
# cursor.executescript(SCHEMA_SQL)
# conn.commit()
# conn.close()
# print(f"Database '{DATABASE}' initialized with products table.")
