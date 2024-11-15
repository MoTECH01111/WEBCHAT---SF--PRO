import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from hashlib import sha256
import sqlite3
import re
from flask import Flask, session, redirect, url_for, request, render_template, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect, CSRFError, validate_csrf

app = Flask(__name__)

app.config.update(
    SECRET_KEY = os.urandom(24),
    #constants for account lockout mechanism (Josh)
    MAX_FAILED_ATTEMPTS = 5,    #if user types password wrong 5 times, lockout
    LOCKOUT_DURATION = timedelta(minutes=15),    #lockout lasts 15 mins
    UPLOAD_FOLDER = 'static/uploads',
    )   

csrf = CSRFProtect(app)
socketio = SocketIO(app)
active_users = set()

#To generate the Fernet encryption key
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)


#Email and username validation done by Erin -- Ensures that the email and username are valid and secure
#To validate the email and username
def is_valid_email(email):
    #Accepts basic email format
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

def is_valid_username(password):
    #Accepts numbers, letters and underscores between 3 and 20 characters
    return bool(re.match(r"^[a-zA-Z0-9_]{3,20}$", password)) 

#Alexandra did this for 
#To Generate a hash with a random salt to encrypt emails
def hash_with_salt(data):
    salt = os.urandom(16)  #To generate a 16-byte salt at random
    salted_data = salt + data.encode()
    hashed_data = sha256(salted_data).hexdigest()
    return salt, hashed_data

#To verify data with the stored hash and salt in the database
def verify_with_salt(salt, data, hashed_data):
    return sha256(salt + data.encode()).hexdigest() == hashed_data

#RSA key generation with serialization and storage for public and private keys
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_key(key, private=False):
    if private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

def store_keys(username, private_key, public_key):
    # Get the current directory where the app.py is located
    app_dir = os.path.dirname(__file__)

    private_key_path = os.path.join(app_dir, f"{username}_private_key.pem")
    public_key_path = os.path.join(app_dir, f"{username}_public_key.pem")

    # Write the private key to a file
    with open(private_key_path, "wb") as private_file:
        private_file.write(serialize_key(private_key, private=True))

    # Write the public key to a file
    with open(public_key_path, "wb") as public_file:
        public_file.write(serialize_key(public_key))

    print(f"Keys for {username} have been saved in the same directory as app.py.")

#To load the keys from the folder
def load_key(username, key_type):
    # Get the current directory where the app.py is located
    app_dir = os.path.dirname(__file__)

    # Define the path to the key
    key_path = os.path.join(app_dir, f"{username}_{key_type}_key.pem")

    try:
        # Read the key from the file
        with open(key_path, "rb") as key_file:
            key_data = key_file.read()
        
        # Load and return the key based on type
        if key_type == 'private':
            return serialization.load_pem_private_key(key_data, password=None)
        elif key_type == 'public':
            return serialization.load_pem_public_key(key_data)
        else:
            raise ValueError("Invalid key type specified. Use 'private' or 'public'.")
    except FileNotFoundError:
        print(f"Key file for {username} ({key_type}) not found.")
        return None

#To encrypt and decrypt messages
def encrypt_message(message):
    return cipher_suite.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message.encode()).decode()

#sign and verify messages for the digital signatures done by Alexandra
def sign_message(private_key_path, message):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key_path, message, signature):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    try:
        public_key.verify(
            bytes.fromhex(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

#Database setup connection and database done by Alexandra
def init_db():
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    failed_attempts INTEGER DEFAULT 0,
                    lockout_time TIMESTAMP)''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender TEXT NOT NULL,
                        receiver TEXT NOT NULL,
                        message TEXT NOT NULL,
                        signature TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS user_salts (
                        username TEXT PRIMARY KEY,
                        email_salt TEXT NOT NULL)''')
    conn.commit()
    conn.close()

#function to add necessary columns for lockout mechanism to database - Josh
def alter_users_table():
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    # attempt to add the 'failed_attempts' column to the users table
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
    except sqlite3.OperationalError as e:
        # if an OperationalError occurs, check if its due to the column already existing
        if 'duplicate column name' in str(e):
            pass        #column already exists, do nothing and proceed
        else:
            raise       #if its a different error, re-raise the exception
    # attempt to add the 'lockout_time' column to the users table
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN lockout_time TIMESTAMP")
    except sqlite3.OperationalError as e:
        if 'duplicate column name' in str(e):
            pass    #column already exists
        else:
            raise
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('chat'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        #This will get the plain text password from the system
        #(generate_password_hash()) this uses secure hashing algorithm to convert the plain text password
        password = generate_password_hash(request.form['password'])
        private_key, public_key = generate_rsa_keypair()
        email_salt, hashed_email = hash_with_salt(email)

        if not is_valid_email(email) or not is_valid_username(username):
            return "Invalid email or username. Please try again."

        try:
            conn = sqlite3.connect("chat.db")
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, hashed_email, password)
            )
            cursor.execute(
                "INSERT INTO user_salts (username, email_salt) VALUES (?, ?)",
                (username, email_salt.hex())
            )
            conn.commit()
            conn.close()

            store_keys(username, private_key, public_key)

            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username or email already taken. Please choose another."

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # check if the user is already logged in
    if 'username' in session:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        login_input = request.form['login']     # get login credentials from the form
        password = request.form['password']

        # connect to database
        conn = sqlite3.connect("chat.db")
        cursor = conn.cursor()
        #retrieve the user record that matches the provided username or email
        cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (login_input, login_input))
        user = cursor.fetchone()

        if user:   
            #Josh code 
            # extract user details from the database records
            user_id = user[0]
            username = user[1]
            stored_password = user[2]
            hashed_email = user[3]
            failed_attempts = user[4] if user[4] else 0     # number of failed login attempts
            lockout_time = user[5]      # timestamp when the account was locked

            #convert lockout_time from string to datetime object, if not None
            if lockout_time:
                lockout_time = datetime.strptime(lockout_time, '%Y-%m-%d %H:%M:%S.%f')

                #check if account is locked
                if datetime.now() < lockout_time + (app.config['LOCKOUT_DURATION']):
                    #account is locked
                    remaining_lockout = (lockout_time + (app.config['LOCKOUT_DURATION'])) - datetime.now()
                    minutes, seconds = divmod(remaining_lockout.total_seconds(), 60)
                    conn.close()
                    return f"Account locked due to multiple failed login attempts. Try again in {int(minutes)} minutes and {int(seconds)} seconds."
                else:
                    #lockout duration has passed, so reset lockout_time and failed_attempts
                    cursor.execute("UPDATE users SET failed_attempts = 0, lockout_time = NULL WHERE id = ?", (user_id,))
                    conn.commit()
                    failed_attempts = 0
                    lockout_time = None
            else:
                lockout_time = None     # no lockout_time means the account is not locked


            if '@' in login_input:
                cursor.execute("SELECT email_salt FROM user_salts WHERE username = ?", (user[1],))#added by Alexandra
                salt_row = cursor.fetchone()
                if salt_row:
                    email_salt = bytes.fromhex(salt_row[0])
                    if not verify_with_salt(email_salt, login_input, user[3]):
                        #email verification failed
                        failed_attempts += 1
                        # update the failed_attempts count in the database
                        cursor.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed_attempts, user_id))
                        conn.commit()

                        if failed_attempts >= (app.config['MAX_FAILED_ATTEMPTS']):
                            #lock the account by setting lockout_time
                            lockout_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                            cursor.execute("UPDATE users SET lockout_time = ? WHERE id = ?", (lockout_time_str, user_id))
                            conn.commit()
                            conn.close()
                            return f"Account locked due to multiple failed login attempts. Try again in {(app.config['LOCKOUT_DURATION'])} minutes."
                        else:
                            # inform user of how many attempts remain
                            attempts_left = (app.config['MAX_FAILED_ATTEMPTS']) - failed_attempts
                            conn.close()
                            return f"Invalid email or password. {attempts_left} attempts remaining."
                    else:
                        # email verification passed
                        conn.close()
                        return "Invalid email or password."
            
            #verify password
            if check_password_hash(stored_password, password):
                #successful login
                session['username'] = username      #set the session variable
                #reset failed attempts and lockout time
                cursor.execute("UPDATE users SET failed_attempts = 0, lockout_time = NULL WHERE id = ?", (user_id,))
                conn.commit()
                conn.close()
                return redirect(url_for('chat'))
            else: 
                #Password is incorrect, increment failed_attempts
                failed_attempts += 1
                cursor.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed_attempts, user_id))
                conn.commit()

                if failed_attempts >= (app.config['MAX_FAILED_ATTEMPTS']):
                    #Lock the account by setting lockout_time
                    lockout_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                    cursor.execute("UPDATE users SET lockout_time = ? WHERE id = ?", (lockout_time_str, user_id))
                    conn.commit()
                    conn.close()
                    return f"Account locked due to multiple failed login attempts. Try again in {(app.config['LOCKOUT_DURATION'])} minutes."
                else: 
                    #inform user of the remaining attempts
                    attempts_left = (app.config['MAX_FAILED_ATTEMPTS']) - failed_attempts
                    conn.close()
                    return f"Invalid username or password. {attempts_left} attempts remaining."
                
        # close the database connection if user is not found
        conn.close()
        return "Invalid username/email or password."

    return render_template('login.html')

@socketio.on('join')
def handle_join(username):
    active_users.add(username)
    session['username'] = username
    join_room(username)
    emit('update_user_list', list(active_users), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username and username in active_users:
        active_users.remove(username)
        leave_room(username)
        emit('update_user_list', list(active_users), broadcast=True)

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    return render_template('chat.html', username=username, active_users=list(active_users))

@socketio.on('send_message')
def handle_message(data):
    # Check if the user is logged in
    sender = session.get('username')
    if not sender:
        emit('error', {'message': 'You must be logged in to send messages.'})
        return  # Return early if not logged in

    receiver = data['receiver']
    message = data['message']
    mediaUrl = data.get('mediaUrl')

    # Encrypt and sign the message
    private_key_path = f"{sender}_private_key.pem"
    signature = sign_message(private_key_path, message)
    encrypted_message = encrypt_message(message)

    #To save the messages to the database
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender, receiver, message, signature) VALUES (?, ?, ?, ?)",
                   (sender, receiver, encrypted_message, signature.hex()))
    conn.commit()
    conn.close()

    # Emit the message to the receiver
    emit('new_message', {
        'sender': sender,
        'message': decrypt_message(encrypted_message),
        'signature': signature.hex(),
        'mediaUrl': mediaUrl
    }, room=receiver)

    # Notify the receiver about the new message
    emit('notification', {'sender': sender, 'message': 'You have a new message'}, room=receiver)

@app.route('/fetch_messages', methods=['GET'])
def fetch_messages():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT sender, message, signature FROM messages WHERE receiver = ?", (username,))
    messages = cursor.fetchall()
    conn.close()
    
    #Digital signature is for verifying the messages authenticity 
    verified_messages = [] #
    for sender, encrypted_message, signature in messages:
        public_key_path = f"{sender}_public_key.pem"
        decrypted_message = decrypt_message(encrypted_message)
        signature_bytes = bytes.fromhex(signature)
        #verify_signature(public_key_path, decrypted_message, signature_bytes) will check for the authenticity of the message
        #If the signatures matches it should confirm the sender created the message and has not been messed with
        #If the signature is invalid it indicated tampering or a mismatch in keys 
        if verify_signature(public_key_path, decrypted_message, signature_bytes):
            verified_messages.append({"sender": sender, "message": decrypted_message})
        else:
            verified_messages.append({"sender": sender, "message": "[Signature verification failed]"})

    return jsonify(verified_messages)

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)  # Remove the username from session to log out
    return redirect(url_for('login'))  # Redirect to login page after logging out

#erins code -----
allowedExtensions = {'png', 'jpg', 'jpeg', 'gif'}
uploadFolder = 'static/uploads'
app.config['uploadFolder'] = uploadFolder

if not os.path.exists(uploadFolder):
    os.makedirs(uploadFolder)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowedExtensions

@app.route('/upload', methods=['POST'])
def uploadFile():
    try:
        validate_csrf(request.form.get('csrf_token'))
    except Exception as e:
        return jsonify({"error": "Invalid CSRF token"}), 400
    
    if 'media' not in request.files:
        return jsonify({'error': 'no file part'}), 400

    file = request.files['media']

    if file.filename == '':
        return jsonify({'error': 'no selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filePath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filePath)

        mediaUrl = url_for('static', filename=f'uploads/{filename}')
        return jsonify({'url': mediaUrl}), 200

    return jsonify({'error': 'invalid file type'}), 400

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({"error": "CSRF token missing or invalid"}), 400


if __name__ == "__main__":
    init_db()
    alter_users_table()
    socketio.run(app, debug=True)

    