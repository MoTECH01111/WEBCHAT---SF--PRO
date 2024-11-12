from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

<<<<<<< Updated upstream
=======
# Initialize Flask-SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

active_users = set()

>>>>>>> Stashed changes
# Generate a Fernet encryption key
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Database setup
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

# Encrypt function for messages
def encrypt_message(message, username):
    return cipher_suite.encrypt(f"{username}:{message}".encode()).decode()

# Decrypt function for messages
def decrypt_message(encrypted_message):
    decrypted = cipher_suite.decrypt(encrypted_message.encode()).decode()
    return decrypted.split(":", 1)[1]  # Return only the message part

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        
        try:
            conn = sqlite3.connect("chat.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username already taken. Please choose another."
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect("chat.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('chat'))
        else:
            return "Invalid username or password."
    
    return render_template('login.html')

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        sender = session['username']
        receiver = request.json['receiver']
        message = request.json['message']
        encrypted_message = encrypt_message(message, sender)

        conn = sqlite3.connect("chat.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
                       (sender, receiver, encrypted_message))
        conn.commit()
        conn.close()
        
        return jsonify({"reply": "Message sent successfully!"})
    
    return render_template('chat.html')

@app.route('/fetch_messages', methods=['GET'])
def fetch_messages():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT sender, message FROM messages WHERE receiver = ?", (username,))
    messages = cursor.fetchall()
    conn.close()

    decrypted_messages = [{"sender": sender, "message": decrypt_message(message)} for sender, message in messages]
    
    return jsonify(decrypted_messages)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/save_password', methods=['POST'])
def save_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    password_manager_entry = request.form['password_manager']
    encrypted_entry = encrypt_message(password_manager_entry, username)

    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
                   (username, username, encrypted_entry))
    conn.commit()
    conn.close()
    
    return "Password saved to manager successfully."

if __name__ == "__main__":
    init_db()
<<<<<<< Updated upstream
    app.run(debug=True)
=======
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)
>>>>>>> Stashed changes
