from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import sqlite3
import os
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize Flask-SocketIO
socketio = SocketIO(app)
active_users = set()

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
    # Check if the user is already logged in, if so, redirect to the chat page
    if 'username' in session:
        return redirect(url_for('chat'))
    
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
    # Check if the user is already logged in, if so, redirect to the chat page
    if 'username' in session:
        return redirect(url_for('chat'))
    
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
    if request.method == 'POST':
        sender = session['username']
        receiver = request.json['receiver']
        message = request.json['message']
        encrypted_message = encrypt_message(message, sender)

        # Insert encrypted message into the database
        conn = sqlite3.connect("chat.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
                       (sender, receiver, encrypted_message))
        conn.commit()
        conn.close()

        # Emit message to the receiver using SocketIO
        emit('new_message', {'sender': sender, 'message': decrypt_message(encrypted_message)}, room=receiver)
        return jsonify({"sender": sender, "message": decrypt_message(encrypted_message)})
    
    return render_template('chat.html')

# SocketIO event handler to send messages to specific users
@socketio.on('join')
def handle_join(username):
    # Add the user to the active users set
    active_users.add(username)
    session['username'] = username
    join_room(username)  # This ensures each user joins their unique room

    # Broadcast the updated list of active users to all clients
    emit('update_user_list', list(active_users), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    # Retrieve the username from the session or a custom method you use
    username = session.get('username')
    if username and username in active_users:
        active_users.remove(username)
        # Broadcast the updated list after user leaves
        emit('update_user_list', list(active_users), broadcast=True)


@socketio.on('send_message')
def handle_message(data):
    sender = session['username']
    receiver = data['receiver']
    message = data['message']
    mediaUrl = data.get('mediaUrl')

    encrypted_message = encrypt_message(message, sender)

    # Insert encrypted message into the database
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
                   (sender, receiver, encrypted_message))
    conn.commit()
    conn.close()

    # Emit encrypted message to receiver’s room
    emit('new_message', {
        'sender': sender,
        'message': decrypt_message(encrypted_message), 
        'mediaUrl': mediaUrl},
        room=receiver)

    # Notify the receiver about the new message
    emit('notification', {
        'sender': sender, 
        'message': 'You have a new message'}, 
        room=receiver)

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

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)  # Remove the username from session to log out
    return redirect(url_for('login'))  # Redirect to login page after logging out

# erins code -----

allowedExtensions = {'png', 'jpg', 'jpeg', 'gif'}
uploadFolder = 'static/uploads'
app.config['uploadFolder'] = uploadFolder

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowedExtensions

@app.route('/upload', methods=['POST'])
def uploadFile():
    if 'media' not in request.files:
        return jsonify({'error': 'no file part'}), 400
    
    file = request.files['media']

    if file.filename == '':
        return jsonify({'error': 'no selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filePath = os.path.join(app.config['uploadFolder'], filename)
        file.save(filePath)

        mediaUrl = url_for('static', filename=f'uploads/{filename}')
        return jsonify({'url': mediaUrl}), 200
    
    return jsonify({'error': 'invalid file type'}), 400


if __name__ == "__main__":
    init_db()
    socketio.run(app, debug=True)
