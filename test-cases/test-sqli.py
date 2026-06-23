# SQL Injection Test Case — CWE-89, OWASP A03:2021
# This file contains INTENTIONAL vulnerabilities for testing the security scanner.

import sqlite3

def get_user_by_id(user_id):
    """VULNERABLE: SQL Injection via string formatting"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABILITY: Direct string interpolation in SQL query
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def search_users(name):
    """VULNERABLE: SQL Injection via string concatenation"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABILITY: String concatenation in SQL
    cursor.execute("SELECT * FROM users WHERE name='" + name + "'")
    return cursor.fetchall()

def get_user_orders(user_id, status):
    """VULNERABLE: Multiple injection points"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABILITY: f-string with multiple user inputs
    query = f"SELECT * FROM orders WHERE user_id={user_id} AND status='{status}'"
    cursor.execute(query)
    return cursor.fetchall()

# SAFE EXAMPLE (for comparison):
# cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
