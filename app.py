from flask import Flask, request, redirect, render_template, session, url_for, abort, current_app
import sqlite3
import os
from functools import wraps
import bcrypt
import base64
import jwt
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', Fernet.generate_key().decode())
app.config['SECRET_KEY'] = app.secret_key

# Inisialisasi database
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    try:
        # Tambahkan admin default 
        admin_password = "P@ssw0rd"
        hashed_bytes = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
        hashed_password = base64.b64encode(hashed_bytes).decode('utf-8')
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                       ("admin", hashed_password, "admin"))
    except sqlite3.IntegrityError:
        pass  # Jika sudah ada
    conn.commit()
    conn.close()

def get_user_from_db(username):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {
            'id': user[0],
            'username': user[1],
            'password': user[2],
            'role': user[3]
        }
    return None

# Admin role decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))

        user = get_user_from_db(session['username'])
        if not user or user['role'] != 'admin':
            abort(403)

        return f(*args, **kwargs)
    return decorated_function

# JWT token 
def create_token(user):
    return jwt.encode({
        'sub': user['username'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }, current_app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except:
        return None

# Home
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('profile'))
    return redirect(url_for('login'))

# Login 
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            hashed_bytes = base64.b64decode(user[2].encode('utf-8'))
            if bcrypt.checkpw(password.encode('utf-8'), hashed_bytes):
                session['username'] = user[1]
                session['role'] = user[3]
                return redirect(url_for('profile'))
        else:
            error = "Invalid credentials"

    return render_template('login.html', error=error)

# Register 
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        hashed_password = base64.b64encode(hashed_bytes).decode('utf-8')

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = "Username already exists"
        finally:
            conn.close()
    return render_template('register.html', error=error)

# Profile 
@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    role = session.get('role', 'user')

    return render_template('profile.html', username=username, role=role)

# Admin Page 
@app.route('/admin')
@admin_required
def admin():
    return render_template('admin.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
