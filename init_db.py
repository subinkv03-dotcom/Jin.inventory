#!/usr/bin/env python3
"""
Improved SQLite DB initialization for Jin.inventory

- Enables foreign keys
- Sets WAL journaling
- Adds audit_logs table + triggers for products, orders, users, locations
- Adds useful indexes and constraints
- Provides helper to create users with hashed passwords
"""

import sqlite3
import json
import os
import hashlib
import secrets
from datetime import datetime

# Try to use bcrypt for secure password hashing if available.
try:
    import bcrypt  # type: ignore
    _HAS_BCRYPT = True
except Exception:
    _HAS_BCRYPT = False

DB_PATH = os.environ.get("JIN_INVENTORY_DB", "company_inventory.db")

def hash_password(password: str) -> str:
    """
    Return a hashed password. Prefer bcrypt if available, otherwise use salted sha256.
    The returned string is self-describing: starts with 'bcrypt$' or 'sha256$'.
    """
    if _HAS_BCRYPT:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        return "bcrypt$" + hashed.decode("utf-8")
    # Fallback (less ideal): salted SHA-256
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"sha256${salt}${digest}"

def verify_password(password: str, stored: str) -> bool:
    """
    Verify password against stored hash.
    """
    if stored.startswith("bcrypt$") and _HAS_BCRYPT:
        hashed = stored.split("bcrypt$", 1)[1].encode("utf-8")
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    if stored.startswith("sha256$"):
        _, salt, digest = stored.split("$", 2)
        check = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        return secrets.compare_digest(check, digest)
    # Unknown format
    return False

def init_db(path: str = DB_PATH):
    # Connect and configure
    conn = sqlite3.connect(path)
    # Return rows as dict-like
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Recommended pragmas
    cur.execute("PRAGMA foreign_keys = ON;")
    # WAL mode helps concurrency for readers/writers
    cur.execute("PRAGMA journal_mode = WAL;")
    # Reduce sync for speed (tradeoff durability). Adjust to your needs.
    cur.execute("PRAGMA synchronous = NORMAL;")

    # Create tables
    cur.executescript("""
    -- Locations
    CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE
    );

    -- Products
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT,
        current_stock INTEGER NOT NULL DEFAULT 0,
        reorder_level INTEGER NOT NULL DEFAULT 10,
        unit_price REAL,
        UNIQUE(name)
    );

    -- Users
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'staff' CHECK(role IN ('admin','staff')),
        location_id INTEGER,
        FOREIGN KEY(location_id) REFERENCES locations(id) ON DELETE SET NULL
    );

    -- Orders
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY,
        product_id INTEGER,
        user_id INTEGER,
        location_id INTEGER,
        quantity INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','Approved','Shipped','Cancelled')),
        order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE SET NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(location_id) REFERENCES locations(id) ON DELETE SET NULL
    );

    -- Audit logs
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY,
        table_name TEXT NOT NULL,
        operation TEXT NOT NULL, -- INSERT, UPDATE, DELETE
        row_id INTEGER, -- primary key value of affected row (if available)
        changed_data TEXT, -- JSON (string) describing old/new row
        acting_user_id INTEGER, -- set by application when possible
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Simple table to let application set current acting user for triggers.
    -- The application can set: INSERT OR REPLACE INTO current_user (id) VALUES (<user_id>);
    CREATE TABLE IF NOT EXISTS current_user ( id INTEGER );
    """)

    # Indexes for performance
    cur.executescript("""
    CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);
    CREATE INDEX IF NOT EXISTS idx_products_name ON products(name);
    CREATE INDEX IF NOT EXISTS idx_orders_product_id ON orders(product_id);
    CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
    CREATE INDEX IF NOT EXISTS idx_orders_location_id ON orders(location_id);
    CREATE INDEX IF NOT EXISTS idx_users_location_id ON users(location_id);
    CREATE INDEX IF NOT EXISTS idx_audit_table ON audit_logs(table_name);
    """)

    # Drop existing triggers if any, then create triggers that log changes to audit_logs.
    # We use explicit json_object() mappings for columns so changed_data is structured JSON.
    # If you add more columns, extend the json_object accordingly.
    cur.executescript("""
    -- PRODUCTS triggers
    DROP TRIGGER IF EXISTS products_ai;
    CREATE TRIGGER products_ai AFTER INSERT ON products
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'products',
        'INSERT',
        NEW.id,
        json_object(
          'new', json_object(
             'id', NEW.id,
             'name', NEW.name,
             'category', NEW.category,
             'current_stock', NEW.current_stock,
             'reorder_level', NEW.reorder_level,
             'unit_price', NEW.unit_price
          )
        ),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;

    DROP TRIGGER IF EXISTS products_au;
    CREATE TRIGGER products_au AFTER UPDATE ON products
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'products',
        'UPDATE',
        NEW.id,
        json_object(
          'old', json_object(
             'id', OLD.id,
             'name', OLD.name,
             'category', OLD.category,
             'current_stock', OLD.current_stock,
             'reorder_level', OLD.reorder_level,
             'unit_price', OLD.unit_price
          ),
          'new', json_object(
             'id', NEW.id,
             'name', NEW.name,
             'category', NEW.category,
             'current_stock', NEW.current_stock,
             'reorder_level', NEW.reorder_level,
             'unit_price', NEW.unit_price
          )
        ),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;

    DROP TRIGGER IF EXISTS products_ad;
    CREATE TRIGGER products_ad AFTER DELETE ON products
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'products',
        'DELETE',
        OLD.id,
        json_object('old', json_object(
             'id', OLD.id,
             'name', OLD.name,
             'category', OLD.category,
             'current_stock', OLD.current_stock,
             'reorder_level', OLD.reorder_level,
             'unit_price', OLD.unit_price
        )),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;

    -- ORDERS triggers
    DROP TRIGGER IF EXISTS orders_ai;
    CREATE TRIGGER orders_ai AFTER INSERT ON orders
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'orders',
        'INSERT',
        NEW.id,
        json_object('new', json_object(
          'id', NEW.id,
          'product_id', NEW.product_id,
          'user_id', NEW.user_id,
          'location_id', NEW.location_id,
          'quantity', NEW.quantity,
          'status', NEW.status,
          'order_date', NEW.order_date
        )),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;

    DROP TRIGGER IF EXISTS orders_au;
    CREATE TRIGGER orders_au AFTER UPDATE ON orders
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'orders',
        'UPDATE',
        NEW.id,
        json_object('old', json_object(
          'id', OLD.id,
          'product_id', OLD.product_id,
          'user_id', OLD.user_id,
          'location_id', OLD.location_id,
          'quantity', OLD.quantity,
          'status', OLD.status,
          'order_date', OLD.order_date
        ), 'new', json_object(
          'id', NEW.id,
          'product_id', NEW.product_id,
          'user_id', NEW.user_id,
          'location_id', NEW.location_id,
          'quantity', NEW.quantity,
          'status', NEW.status,
          'order_date', NEW.order_date
        )),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;

    DROP TRIGGER IF EXISTS orders_ad;
    CREATE TRIGGER orders_ad AFTER DELETE ON orders
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'orders',
        'DELETE',
        OLD.id,
        json_object('old', json_object(
          'id', OLD.id,
          'product_id', OLD.product_id,
          'user_id', OLD.user_id,
          'location_id', OLD.location_id,
          'quantity', OLD.quantity,
          'status', OLD.status,
          'order_date', OLD.order_date
        )),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;

    -- USERS triggers
    DROP TRIGGER IF EXISTS users_ai;
    CREATE TRIGGER users_ai AFTER INSERT ON users
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'users',
        'INSERT',
        NEW.id,
        json_object('new', json_object(
          'id', NEW.id,
          'username', NEW.username,
          'role', NEW.role,
          'location_id', NEW.location_id
        )),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;

    DROP TRIGGER IF EXISTS users_au;
    CREATE TRIGGER users_au AFTER UPDATE ON users
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'users',
        'UPDATE',
        NEW.id,
        json_object('old', json_object(
          'id', OLD.id,
          'username', OLD.username,
          'role', OLD.role,
          'location_id', OLD.location_id
        ), 'new', json_object(
          'id', NEW.id,
          'username', NEW.username,
          'role', NEW.role,
          'location_id', NEW.location_id
        )),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;

    DROP TRIGGER IF EXISTS users_ad;
    CREATE TRIGGER users_ad AFTER DELETE ON users
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'users',
        'DELETE',
        OLD.id,
        json_object('old', json_object(
          'id', OLD.id,
          'username', OLD.username,
          'role', OLD.role,
          'location_id', OLD.location_id
        )),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;

    -- LOCATIONS triggers
    DROP TRIGGER IF EXISTS locations_ai;
    CREATE TRIGGER locations_ai AFTER INSERT ON locations
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'locations',
        'INSERT',
        NEW.id,
        json_object('new', json_object(
          'id', NEW.id,
          'name', NEW.name
        )),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;

    DROP TRIGGER IF EXISTS locations_au;
    CREATE TRIGGER locations_au AFTER UPDATE ON locations
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'locations',
        'UPDATE',
        NEW.id,
        json_object('old', json_object(
          'id', OLD.id,
          'name', OLD.name
        ), 'new', json_object(
          'id', NEW.id,
          'name', NEW.name
        )),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;

    DROP TRIGGER IF EXISTS locations_ad;
    CREATE TRIGGER locations_ad AFTER DELETE ON locations
    BEGIN
      INSERT INTO audit_logs (table_name, operation, row_id, changed_data, acting_user_id)
      VALUES (
        'locations',
        'DELETE',
        OLD.id,
        json_object('old', json_object(
          'id', OLD.id,
          'name', OLD.name
        )),
        (SELECT id FROM current_user LIMIT 1)
      );
    END;
    """)

    conn.commit()
    conn.close()
    print(f"Database initialized successfully at: {path}")

def create_user(username: str, password: str, role: str = "staff", location_id: int | None = None):
    """
    Helper to insert a user with hashed password.
    """
    pwd = hash_password(password)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")
    cur.execute(
        "INSERT INTO users (username, password, role, location_id) VALUES (?, ?, ?, ?)",
        (username, pwd, role, location_id)
    )
    conn.commit()
    conn.close()

def set_acting_user(user_id: int | None):
    """
    Application should call this before running operations that should be audited.

    Example:
      set_acting_user(42)
      # run insert/update/delete statements...
      set_acting_user(None)  # clear when done
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM current_user;")
    if user_id is not None:
        cur.execute("INSERT INTO current_user (id) VALUES (?)", (user_id,))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    # Initialize DB and create a default admin user if none exists
    init_db()
    # Create an initial admin user if users table is empty (useful for first-run)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(1) FROM users;")
    if cur.fetchone()[0] == 0:
        print("No users found — creating default admin user 'admin' with password 'admin'.")
        create_user("admin", "admin", role="admin")
        print("Default admin created. Please change password immediately.")
    conn.close()