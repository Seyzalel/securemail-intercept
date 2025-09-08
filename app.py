import os
import re
import logging
from datetime import timedelta, datetime
from urllib.parse import quote_plus
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = 'qvF@9mG#7rKpX3Z!eA6Lw2Y^uJh5NbTdCxMzVb1RsEpQgUoIiHtKk+0P*sDfWnEl'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

logging.basicConfig(level=logging.INFO)
USER = quote_plus(os.environ.get('DB_USER', 'seyzalel_db_user'))
PWD = quote_plus(os.environ.get('DB_PASS', 'pAd1F4iscPwdyRvV'))
MONGO_URI = f"mongodb+srv://{USER}:{PWD}@securemail.r9xmnzl.mongodb.net/?retryWrites=true&w=majority&appName=SecureMail"
client = MongoClient(MONGO_URI)
db = client['securemail']
db.users.create_index([('username_lower', ASCENDING)], unique=True)
db.users.create_index([('email_lower', ASCENDING)], unique=True)

def is_email(v):
    return re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', v) is not None

def valid_password(p):
    if not p or len(p) < 8:
        return False
    if not re.search(r'[A-Z]', p):
        return False
    if not re.search(r'[0-9]', p):
        return False
    return True

def login_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return _wrap

@app.after_request
def secure_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return resp

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    username = (request.form.get('username') or '').strip()
    email = (request.form.get('email') or '').strip()
    password = request.form.get('password') or ''
    confirm = request.form.get('confirmPassword') or ''
    terms = request.form.get('terms')
    if not username or len(username) < 3:
        return jsonify({'ok': False, 'error': 'Nome de usuário inválido.'}), 400
    if not is_email(email):
        return jsonify({'ok': False, 'error': 'E-mail inválido.'}), 400
    if not valid_password(password):
        return jsonify({'ok': False, 'error': 'Senha fraca.'}), 400
    if password != confirm:
        return jsonify({'ok': False, 'error': 'As senhas não coincidem.'}), 400
    if not terms:
        return jsonify({'ok': False, 'error': 'É necessário aceitar os termos.'}), 400
    existing = db.users.find_one({'$or': [{'username_lower': username.lower()}, {'email_lower': email.lower()}]})
    if existing:
        return jsonify({'ok': False, 'error': 'Usuário ou e-mail já cadastrado.'}), 409
    try:
        user = {
            'username': username,
            'username_lower': username.lower(),
            'email': email,
            'email_lower': email.lower(),
            'password_hash': generate_password_hash(password),
            'created_at': datetime.utcnow(),
            'last_login_at': None
        }
        ins = db.users.insert_one(user)
    except DuplicateKeyError:
        return jsonify({'ok': False, 'error': 'Usuário ou e-mail já cadastrado.'}), 409
    session.clear()
    session['user_id'] = str(ins.inserted_id)
    session['username'] = username
    session.permanent = False
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    identity = (request.form.get('identity') or '').strip()
    password = request.form.get('password') or ''
    remember = request.form.get('remember')
    if not identity:
        return jsonify({'ok': False, 'error': 'Informe usuário ou e-mail.'}), 400
    if '@' in identity:
        if not is_email(identity):
            return jsonify({'ok': False, 'error': 'E-mail inválido.'}), 400
        q = {'email_lower': identity.lower()}
    else:
        if len(identity) < 3:
            return jsonify({'ok': False, 'error': 'Usuário inválido.'}), 400
        q = {'username_lower': identity.lower()}
    user = db.users.find_one(q)
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'ok': False, 'error': 'Credenciais inválidas.'}), 401
    db.users.update_one({'_id': user['_id']}, {'$set': {'last_login_at': datetime.utcnow()}})
    session.clear()
    session['user_id'] = str(user['_id'])
    session['username'] = user['username']
    session.permanent = bool(remember)
    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
