import sqlite3

def init_db():
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender TEXT NOT NULL,
                        receiver TEXT NOT NULL,
                        message TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

def add_email_column():
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if "email" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT UNIQUE")
        print("Email column added to the users table.")
    else:
        print("Email column already exists in the users table.")
    
    conn.commit()
    conn.close()

add_email_column()
