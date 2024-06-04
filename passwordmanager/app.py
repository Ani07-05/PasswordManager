from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import logging

app = Flask(__name__)
app.secret_key = 'supersecretkey'

logging.basicConfig(level=logging.DEBUG)

def get_db_connection():
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row  # This will allow us to access the columns by their names
        return conn
    except sqlite3.Error as e:
        app.logger.error(f"Database connection error: {e}")
        return None

@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        conn = get_db_connection()
        if conn is None:
            flash('Database connection failed')
            return redirect(url_for('register'))

        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user:
            flash('Username already exists')
            conn.close()
            return redirect(url_for('register'))

        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()

        flash('Registered successfully! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        if conn is None:
            flash('Database connection failed')
            return redirect(url_for('login'))

        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    if conn is None:
        flash('Database connection failed')
        return redirect(url_for('login'))
    
    passwords = conn.execute('SELECT * FROM passwords WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return render_template('dashboard.html', passwords=passwords)

@app.route('/add_password', methods=['POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    site_name = request.form['site_name']
    site_url = request.form['site_url']
    site_password = request.form['site_password']

    conn = get_db_connection()
    if conn is None:
        flash('Database connection failed')
        return redirect(url_for('dashboard'))

    conn.execute('INSERT INTO passwords (user_id, site_name, site_url, site_password) VALUES (?, ?, ?, ?)',
                 (session['user_id'], site_name, site_url, site_password))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))

@app.route('/update_password/<int:id>', methods=['POST'])
def update_password(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    site_name = request.form['site_name']
    site_url = request.form['site_url']
    site_password = request.form['site_password']

    conn = get_db_connection()
    if conn is None:
        flash('Database connection failed')
        return redirect(url_for('dashboard'))

    conn.execute('UPDATE passwords SET site_name = ?, site_url = ?, site_password = ? WHERE id = ? AND user_id = ?',
                 (site_name, site_url, site_password, id, session['user_id']))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
