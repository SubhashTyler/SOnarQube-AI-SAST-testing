import os
import json
import sqlite3
import hashlib
import flask
import logging

from security import generate_password_hash, check_password_hash

app = flask.Flask(__name__)

# Hardcoded sensitive information
DATABASE = "secure_app.db"
SECRET_KEY = "verysecretkey"  # Vulnerable: Hardcoded secret

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    return conn

@app.route('/api/register', methods=['POST'])
def register():
    data = flask.request.json
    username = data.get('username')
    password = data.get('password')

    # Unique: Missing input validation (e.g., username length)
    if len(username) < 5:
        return json.dumps({"message": "Username too short!"}), 400

    # Unique: Password is hashed but no salt used
    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()
    return json.dumps({"message": "User registered!"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = flask.request.json
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    # Unique: Password comparison should use a timing-safe comparison to prevent timing attacks
    if user and check_password_hash(user[1], password):
        return json.dumps({"message": "Login successful!"})
    return json.dumps({"message": "Invalid credentials"}), 401

@app.route('/api/data', methods=['POST'])
def get_data():
    data = flask.request.json
    user_input = data.get('input')

    # Unique: No input sanitization for a potential command injection vulnerability
    os.system(user_input)  # Dangerous: Executes arbitrary shell commands

    return json.dumps({"message": "Command executed!"})

@app.route('/api/admin', methods=['POST'])
def admin_action():
    data = flask.request.json
    token = data.get('token')

    # Unique: Token-based authentication without expiration
    if token == SECRET_KEY:
        return json.dumps({"message": "Admin access granted!"})
    return json.dumps({"message": "Access denied!"}), 403

@app.route('/api/file', methods=['POST'])
def upload_file():
    # Unique: No file type validation, allowing execution of malicious scripts
    if 'file' not in flask.request.files:
        return json.dumps({"message": "No file part"}), 400
    file = flask.request.files['file']
    if file.filename == '':
        return json.dumps({"message": "No selected file"}), 400

    # Vulnerable: Save files to a location that could be executed
    file.save(os.path.join("/uploads", file.filename))

    return json.dumps({"message": "File uploaded successfully!"})

@app.route('/api/health', methods=['GET'])
def health_check():
    # Unique: Returning detailed error messages can expose sensitive information
    return json.dumps({"status": "healthy", "database": DATABASE})

def main():
    app.run(debug=True)  # Vulnerable: Debug mode should not be enabled in production

if __name__ == '__main__':
    main()

from flask import Flask, request, jsonify, send_from_directory
app = Flask(__name__)

# Initialize the database
def init_db():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL
                     )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS posts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        content TEXT NOT NULL,
                        user_id INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                     )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT NOT NULL,
                        user_id INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                     )''')
    conn.commit()
    conn.close()

init_db()

# Helper function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Vulnerable to SQL Injection
def get_user(user_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # SQL Injection
    user = cursor.fetchone()
    conn.close()
    return user

# User registration with plaintext password storage
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing fields'}), 400

    username = data['username']
    password = data['password']  # Storing plaintext password

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (username, hash_password(password)))  # Vulnerable to SQL Injection
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()

    return jsonify({'message': 'User registered successfully'}), 201

# Unhandled exception in login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing fields'}), 400

    username = data['username']
    password = data['password']

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")  # SQL Injection
    user = cursor.fetchone()
    conn.close()

    if user and user[2] == hash_password(password):  # Checking against hashed password
        return jsonify({'message': 'Login successful'}), 200

    return jsonify({'error': 'Invalid credentials'}), 401

# File upload vulnerability
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    user_id = request.form.get('user_id')  # No validation on user_id

    # No file type validation and saving files directly
    file.save(os.path.join('uploads', file.filename))
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO files (filename, user_id) VALUES (?, ?)", (file.filename, user_id))  # SQL Injection
    conn.commit()
    conn.close()

    return jsonify({'message': 'File uploaded successfully'}), 200

# Cross-Site Scripting (XSS) vulnerability
@app.route('/api/posts', methods=['POST'])
def create_post():
    data = request.json
    title = data.get('title')
    content = data.get('content')
    user_id = data.get('user_id')

    if not title or not content:
        return jsonify({'error': 'Missing title or content'}), 400

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)",
                   (title, content, user_id))  # Storing user input without sanitization
    conn.commit()
    conn.close()

    return jsonify({'message': 'Post created successfully'}), 201

# Information exposure in fetching posts
@app.route('/api/posts/<post_id>', methods=['GET'])
def fetch_post(post_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM posts WHERE id = {post_id}")  # SQL Injection
    post = cursor.fetchone()
    conn.close()

    if post:
        return jsonify({'post': post}), 200
    return jsonify({'error': 'Post not found'}), 404

# Insecure Direct Object Reference
@app.route('/api/users/<user_id>/posts', methods=['GET'])
def user_posts(user_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM posts WHERE user_id = {user_id}")  # SQL Injection
    posts = cursor.fetchall()
    conn.close()
    return jsonify({'posts': posts}), 200

# Logging sensitive information
@app.route('/api/logs', methods=['POST'])
def log_event():
    data = request.json
    user_id = data.get('user_id')
    action = data.get('action')
    if user_id and action:
        print(f"User {user_id} performed action: {action}")  # Logging sensitive info
    return jsonify({'message': 'Log recorded'}), 200

# File download endpoint with lack of authentication
@app.route('/files/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory('uploads', filename)  # No access control

# XSS vulnerability when viewing posts
@app.route('/api/posts/view/<post_id>', methods=['GET'])
def view_post(post_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM posts WHERE id = {post_id}")  # SQL Injection
    post = cursor.fetchone()
    conn.close()

    if post:
        return f"<h1>{post[1]}</h1><p>{post[2]}</p>"  # XSS vulnerability if post content includes HTML
    return jsonify({'error': 'Post not found'}), 404

# Admin route without proper authorization
@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")  # Exposing all users
    users = cursor.fetchall()
    conn.close()
    return jsonify({'users': users}), 200

# Unhandled exception for unknown endpoints
@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'error': 'Page not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)

import os
import json
import flask
import logging
import sqlite3
import hashlib

app = flask.Flask(__name__)

# Hardcoded configuration
DATABASE = "app.db"
SECRET_KEY = "supersecretkey"  # Vulnerable: Hardcoded secret
ADMIN_PASSWORD = "admin123"  # Hardcoded admin password

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    return conn

@app.route('/api/register', methods=['POST'])
def register():
    data = flask.request.json
    username = data.get('username')
    password = data.get('password')

    # Vulnerability: Storing password in plain text
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()
    return json.dumps({"message": "User registered!"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = flask.request.json
    username = data.get('username')
    password = data.get('password')

    # Vulnerable: No password hashing, using plain text comparison
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and user[1] == password:  # Insecure comparison
        return json.dumps({"message": "Login successful!"})
    return json.dumps({"message": "Invalid credentials"}), 401

@app.route('/api/data', methods=['POST'])
def get_data():
    data = flask.request.json
    user_input = data.get('input')

    # Severe vulnerability: Using eval() on user input
    result = eval(user_input)

    # Potential SQL injection
    sql_query = f"SELECT * FROM users WHERE username = '{data['username']}'"
    # execute_sql(sql_query)  # Hypothetical function

    return json.dumps({"result": result})

@app.route('/api/admin', methods=['POST'])
def admin_action():
    data = flask.request.json
    password = data.get('password')

    # Vulnerable: Hardcoded password check
    if password == ADMIN_PASSWORD:
        return json.dumps({"message": "Admin access granted!"})
    return json.dumps({"message": "Access denied!"}), 403

@app.route('/api/upload', methods=['POST'])
def upload_file():
    # Vulnerable: Allowing unrestricted file uploads
    if 'file' not in flask.request.files:
        return json.dumps({"message": "No file part"}), 400
    file = flask.request.files['file']
    if file.filename == '':
        return json.dumps({"message": "No selected file"}), 400
    
    file.save(os.path.join("/uploads", file.filename))  # Insecure path

    return json.dumps({"message": "File uploaded successfully!"})

@app.route('/api/data_hash', methods=['POST'])
def data_hash():
    data = flask.request.json
    sensitive_data = data.get('sensitive_data')

    # Vulnerability: Using MD5 (not secure)
    md5_hash = hashlib.md5(sensitive_data.encode()).hexdigest()
    return json.dumps({"hash": md5_hash})

def main():
    # Unused variable
    unused_var = "I am not used"
    app.run(debug=True)  # Vulnerable: Debug mode should not be enabled in production

if __name__ == '__main__':
    main()

# Example of a large function
def large_function():
    for i in range(1000):
        print(f"Processing item {i}")
    # A lot of code here...
    for j in range(500):
        print(f"Another processing item {j}")
    for k in range(1000):
        print(f"Yet another item {k}")

class ExampleClass:
    def __init__(self, name):
        self.name = name

    def insecure_method(self):
        # Vulnerable: Directly using user input without validation
        user_input = input("Enter something: ")
        print("User input is:", user_input)

def another_large_function():
    # Simulating a lot of lines of code
    for _ in range(2000):
        pass  # Placeholder for complex logic

    # More complex logic
    for _ in range(1000):
        # Simulate some processing
        pass

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password  # Vulnerable: Storing password in plain text

    def __str__(self):
        return f"User: {self.username}"

def list_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

@app.route('/api/list_users', methods=['GET'])
def api_list_users():
    users = list_users()
    return json.dumps(users)

# More functions to increase code size
def extensive_processing():
    for i in range(100):
        for j in range(100):
            print(f"Processing {i}-{j}")

if __name__ == "__main__":
    main()
