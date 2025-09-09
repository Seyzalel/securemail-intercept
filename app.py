import os
import re
import io
import json
import base64
import hmac
import hashlib
import logging
import string
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus
from functools import wraps

import requests
import qrcode
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient, ASCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'qvF@9mG#7rKpX3Z!eA6Lw2Y^uJh5NbTdCxMzVb1RsEpQgUoIiHtKk+0P*sDfWnEl')
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
db.orders.create_index([('transaction_id', ASCENDING)], unique=True)
db.orders.create_index([('user_id', ASCENDING), ('created_at', ASCENDING)])
db.usage.create_index([('user_id', ASCENDING), ('date', ASCENDING)], unique=True)

PUSHINPAY_TOKEN = "45911|0CnwU402QB1Zw1w15Lf69cDyQZtPd0RovG2TLjgQce6b6af1"
PUSHINPAY_BASE_URL = "https://api.pushinpay.com.br"
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
HEADERS_PP = {"Authorization": f"Bearer {PUSHINPAY_TOKEN}", "Accept": "application/json", "Content-Type": "application/json"}

PLANS = {
    "basic-15": {"key": "basic-15", "name": "Básico", "price_cents": 3500, "price_display": "R$35", "period": "15 dias", "duration_days": 15, "limit_per_day": 5, "support": "WhatsApp", "lifetime": False},
    "standard-30": {"key": "standard-30", "name": "Padrão", "price_cents": 5000, "price_display": "R$50", "period": "30 dias", "duration_days": 30, "limit_per_day": 10, "support": "WhatsApp prioritário", "lifetime": False},
    "advanced-30": {"key": "advanced-30", "name": "Avançado", "price_cents": 9700, "price_display": "R$97", "period": "30 dias", "duration_days": 30, "limit_per_day": 25, "support": "WhatsApp 24/7 prioritário", "lifetime": False},
    "lifetime": {"key": "lifetime", "name": "Vitalício", "price_cents": 13900, "price_display": "R$139", "period": "vitalício", "duration_days": None, "limit_per_day": 20, "support": "WhatsApp 24/7 prioritário", "lifetime": True},
}

NAME_TO_KEY = {v["name"].lower(): k for k, v in PLANS.items()}

PLAN_CODES = {0: None, 1: "basic-15", 2: "standard-30", 3: "advanced-30", 4: "lifetime"}
CODE_BY_KEY = {"basic-15": 1, "standard-30": 2, "advanced-30": 3, "lifetime": 4}

ALPHABET = string.ascii_uppercase + string.digits

def new_user_id(k=12):
    return ''.join(secrets.choice(ALPHABET) for _ in range(k))

def is_email(v):
    return re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', v or '') is not None

def valid_password(p):
    if not p or len(p) < 8:
        return False
    if not re.search(r'[A-Z]', p):
        return False
    if not re.search(r'[0-9]', p):
        return False
    return True

def normalize_cpf(cpf):
    return re.sub(r'\D+', '', cpf or '')

def valid_fullname(n):
    return bool(re.match(r"^[A-Za-zÀ-ÖØ-öø-ÿ'’-]+(?:\s+[A-Za-zÀ-ÖØ-öø-ÿ'’-]+)+$", (n or '').strip()))

def plan_key_from_code(code):
    try:
        c = int(code)
    except Exception:
        c = 0
    return PLAN_CODES.get(c)

def plan_code_from_key(key):
    return CODE_BY_KEY.get(key, 0)

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

def create_pix_pushinpay(value_cents, webhook_url=None, reference=None):
    url = f"{PUSHINPAY_BASE_URL}/api/pix/cashIn"
    body = {"value": int(value_cents)}
    if webhook_url:
        body["webhook_url"] = webhook_url
    if reference:
        body["reference"] = reference
    r = requests.post(url, headers=HEADERS_PP, json=body, timeout=15)
    r.raise_for_status()
    return r.json()

def consult_pp(transaction_id):
    url = f"{PUSHINPAY_BASE_URL}/api/transactions/{transaction_id}"
    r = requests.get(url, headers=HEADERS_PP, timeout=10)
    r.raise_for_status()
    return r.json()

def qr_png_from_payload(payload_text):
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(payload_text)
    qr.make(fit=True)
    img = qr.make_image()
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    bio.seek(0)
    return bio

def parse_pp_response(resp):
    pix_payload = None
    qr_b64 = None
    tid = None
    if isinstance(resp, dict):
        for k in ("qr_code", "payload", "pix", "copiacolapix", "pix_string"):
            if k in resp and resp[k]:
                pix_payload = str(resp[k])
                break
        for k in ("id", "transaction_id", "txid"):
            if k in resp and resp[k]:
                tid = str(resp[k])
                break
        if not pix_payload:
            for k in ("qr_code_base64", "qr_base64", "qrcode_base64"):
                if k in resp and resp[k]:
                    qr_b64 = str(resp[k])
                    break
    if pix_payload:
        img = qr_png_from_payload(pix_payload).getvalue()
        qr_b64 = base64.b64encode(img).decode("utf-8")
    return pix_payload, qr_b64, tid

def order_deadline_secs(created_at):
    exp = created_at + timedelta(minutes=10)
    now = datetime.utcnow()
    return max(0, int((exp - now).total_seconds()))

def set_user_plan_code(user_id, code):
    now = datetime.utcnow()
    key = plan_key_from_code(code)
    info = PLANS.get(key) if key else None
    expires_at = None
    if info and not info["lifetime"]:
        expires_at = now + timedelta(days=info["duration_days"])
    update = {}
    if info:
        update["plan"] = {
            "key": info["key"],
            "name": info["name"],
            "activated_at": now,
            "expires_at": expires_at,
            "limit_per_day": info["limit_per_day"],
            "support": info["support"],
            "period": info["period"],
        }
    else:
        update["plan"] = None
    update["plan_code"] = int(code or 0)
    db.users.update_one({"_id": user_id}, {"$set": update})

def activate_user_plan(user_id, plan):
    code = plan_code_from_key(plan["key"]) if plan else 0
    set_user_plan_code(user_id, code)

def safe_user_id():
    return session.get("user_id")

def get_user():
    uid = safe_user_id()
    if not uid:
        return None
    return db.users.find_one({"_id": uid})

def plan_by_key_or_name(plan_key=None, plan_name=None):
    if plan_key and plan_key in PLANS:
        return PLANS[plan_key]
    if plan_name and plan_name.lower() in NAME_TO_KEY:
        return PLANS[NAME_TO_KEY[plan_name.lower()]]
    return None

def is_user_plan_active(user):
    if not user:
        return False
    code = int(user.get("plan_code") or 0)
    if code <= 0:
        return False
    plan = user.get("plan")
    if not plan:
        key = plan_key_from_code(code)
        info = PLANS.get(key) if key else None
        if not info:
            return False
        if info["lifetime"]:
            return True
        return False
    exp = plan.get("expires_at")
    return exp is None or datetime.utcnow() < exp

def ensure_plan_code(user):
    if not user:
        return None
    if user.get("plan_code") is None:
        code = 0
        p = user.get("plan")
        if p and p.get("key"):
            code = plan_code_from_key(p["key"])
        db.users.update_one({"_id": user["_id"]}, {"$set": {"plan_code": code}})
        user["plan_code"] = code
    return user

def get_effective_plan_info(user):
    plan = user.get("plan") if user else None
    code = int(user.get("plan_code") or 0) if user else 0
    key = plan.get("key") if plan else plan_key_from_code(code)
    info = PLANS.get(key) if key else None
    return info, plan

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
    attempts = 0
    while True:
        attempts += 1
        uid = new_user_id(12)
        user = {'_id': uid, 'username': username, 'username_lower': username.lower(), 'email': email, 'email_lower': email.lower(), 'password_hash': generate_password_hash(password), 'created_at': datetime.utcnow(), 'last_login_at': None, 'plan_code': 0, 'plan': None}
        try:
            db.users.insert_one(user)
            break
        except DuplicateKeyError:
            race = db.users.find_one({'$or': [{'username_lower': username.lower()}, {'email_lower': email.lower()}]})
            if race:
                return jsonify({'ok': False, 'error': 'Usuário ou e-mail já cadastrado.'}), 409
            if attempts < 5:
                continue
            return jsonify({'ok': False, 'error': 'Falha ao gerar ID. Tente novamente.'}), 500
    session.clear()
    session['user_id'] = user['_id']
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
    if not user:
        return jsonify({'ok': False, 'error': 'Credenciais inválidas.'}), 401
    pwd_hash = user.get('password_hash')
    if not pwd_hash or not check_password_hash(pwd_hash, password):
        return jsonify({'ok': False, 'error': 'Credenciais inválidas.'}), 401
    ensure_plan_code(user)
    db.users.update_one({'_id': user['_id']}, {'$set': {'last_login_at': datetime.utcnow()}})
    session.clear()
    session['user_id'] = user['_id']
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

@app.route('/plans', methods=['GET'])
@login_required
def plans():
    return render_template('plans.html')

@app.route('/gateway-pix-payment', methods=['GET'])
@login_required
def gateway_pix_payment():
    return render_template('gateway-pix-payment.html')

@app.route('/api/me', methods=['GET'])
@login_required
def api_me():
    user = get_user()
    user = ensure_plan_code(user)
    info, plan_doc = get_effective_plan_info(user)
    active = is_user_plan_active(user)
    today = datetime.utcnow().date().isoformat()
    usage = db.usage.find_one({'user_id': user['_id'], 'date': today}) if user else None
    used = usage.get('count', 0) if usage else 0
    expires = plan_doc.get('expires_at').isoformat() if plan_doc and plan_doc.get('expires_at') else None
    key = plan_doc.get('key') if plan_doc else (info['key'] if info else None)
    name = plan_doc.get('name') if plan_doc else (info['name'] if info else None)
    limit_per_day = plan_doc.get('limit_per_day') if plan_doc and plan_doc.get('limit_per_day') is not None else (info['limit_per_day'] if info else 0)
    return jsonify({
        'ok': True,
        'user': {'id': user['_id'], 'username': user['username']},
        'plan': {
            'active': active,
            'code': int(user.get('plan_code') or 0),
            'key': key,
            'name': name,
            'limit_per_day': limit_per_day,
            'expires_at': expires
        },
        'usage_today': {'used': used, 'date': today}
    })

@app.route('/api/feature/use', methods=['POST'])
@login_required
def feature_use():
    user = get_user()
    user = ensure_plan_code(user)
    if not is_user_plan_active(user):
        return jsonify({'ok': False, 'error': 'Plano inativo. Atualize seu plano para usar as funcionalidades.'}), 403
    info, plan_doc = get_effective_plan_info(user)
    limit = 0
    if plan_doc and plan_doc.get('limit_per_day') is not None:
        limit = int(plan_doc.get('limit_per_day') or 0)
    elif info:
        limit = int(info.get('limit_per_day') or 0)
    if limit <= 0:
        return jsonify({'ok': False, 'error': 'Seu plano não permite uso. Atualize seu plano.'}), 403
    today = datetime.utcnow().date().isoformat()
    db.usage.find_one_and_update(
        {'user_id': user['_id'], 'date': today},
        {'$setOnInsert': {'user_id': user['_id'], 'date': today, 'count': 0}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    updated = db.usage.find_one_and_update(
        {'user_id': user['_id'], 'date': today, 'count': {'$lt': limit}},
        {'$inc': {'count': 1}},
        return_document=ReturnDocument.AFTER
    )
    if updated is None:
        doc = db.usage.find_one({'user_id': user['_id'], 'date': today}) or {'count': limit}
        return jsonify({'ok': False, 'error': 'Limite diário atingido.', 'used': doc.get('count', limit), 'limit': limit}), 429
    used = updated.get('count', 0)
    remaining = max(0, limit - used)
    return jsonify({'ok': True, 'used': used, 'remaining': remaining, 'limit': limit})

@app.route('/api/pay/create', methods=['POST'])
@login_required
def api_pay_create():
    data = request.get_json(force=True, silent=True) or {}
    plan_key = data.get('plan_key')
    plan_name = data.get('plan_name')
    fullname = (data.get('fullname') or '').strip()
    cpf = normalize_cpf(data.get('cpf'))
    plan = plan_by_key_or_name(plan_key, plan_name)
    if not plan:
        return jsonify({"ok": False, "error": "Plano inválido."}), 400
    if not valid_fullname(fullname):
        return jsonify({"ok": False, "error": "Nome completo inválido."}), 400
    if not re.fullmatch(r'\d{11}', cpf or ''):
        return jsonify({"ok": False, "error": "CPF inválido."}), 400
    user_id = safe_user_id()
    if not user_id:
        return jsonify({"ok": False, "error": "Não autenticado."}), 401
    created_at = datetime.utcnow()
    code = plan_code_from_key(plan['key'])
    reference = f"user:{user_id}|plan:{plan['key']}|code:{code}|ts:{int(created_at.timestamp())}"
    base = request.url_root.rstrip('/')
    webhook_url = base + url_for('pushinpay_webhook')
    try:
        pp_resp = create_pix_pushinpay(plan['price_cents'], webhook_url=webhook_url, reference=reference)
    except Exception:
        return jsonify({"ok": False, "error": "Falha ao criar PIX."}), 502
    pix_payload, qr_b64, tid = parse_pp_response(pp_resp)
    if not tid:
        return jsonify({"ok": False, "error": "Falha ao obter ID da transação."}), 502
    order = {
        "_id": str(os.urandom(12).hex()),
        "user_id": user_id,
        "username": session.get("username"),
        "plan": {k: v for k, v in plan.items()},
        "plan_code": code,
        "fullname": fullname,
        "cpf": cpf,
        "transaction_id": tid,
        "pix_payload": pix_payload,
        "qr_png_base64": qr_b64,
        "pushinpay_response": pp_resp,
        "status": "pending",
        "created_at": created_at,
        "expires_at": created_at + timedelta(minutes=10),
        "paid_at": None,
    }
    try:
        db.orders.insert_one(order)
    except DuplicateKeyError:
        pass
    return jsonify({"ok": True, "redirect": url_for('gateway_pix_payment', tid=tid)}), 201

@app.route('/api/pay/info', methods=['GET'])
@login_required
def api_pay_info():
    tid = request.args.get('tid')
    user_id = safe_user_id()
    order = None
    if tid:
        order = db.orders.find_one({"transaction_id": tid, "user_id": user_id})
    if not order:
        order = db.orders.find_one({"user_id": user_id}, sort=[("created_at", -1)])
    if not order:
        return jsonify({"ok": False, "error": "Pedido não encontrado."}), 404
    now = datetime.utcnow()
    deadline_seconds = max(0, int((order["expires_at"] - now).total_seconds())) if order.get("expires_at") else 0
    return jsonify({
        "ok": True,
        "plan": {
            "key": order["plan"]["key"],
            "name": order["plan"]["name"],
            "price_display": order["plan"]["price_display"],
            "period": order["plan"]["period"],
            "limit_per_day": order["plan"]["limit_per_day"],
            "support": order["plan"]["support"],
        },
        "pix_payload": order.get("pix_payload"),
        "qr_png_base64": order.get("qr_png_base64"),
        "qr_url": url_for('api_pix_qr', transaction_id=order["transaction_id"]),
        "transaction_id": order["transaction_id"],
        "status": order.get("status"),
        "deadline_seconds": deadline_seconds
    })

@app.route('/api/pay/status', methods=['GET'])
@login_required
def api_pay_status():
    tid = request.args.get('tid')
    if not tid:
        return jsonify({"ok": False, "error": "tid ausente."}), 400
    order = db.orders.find_one({"transaction_id": tid, "user_id": safe_user_id()})
    if not order:
        return jsonify({"ok": False, "error": "Pedido não encontrado."}), 404
    status = order.get("status") or "pending"
    if status not in ("paid", "expired"):
        try:
            pp = consult_pp(tid)
            st = None
            for k in ("status", "state", "payment_status"):
                if isinstance(pp, dict) and k in pp:
                    st = str(pp[k]).lower()
                    break
            if st in ("paid", "pago", "success", "confirmed"):
                db.orders.find_one_and_update({"_id": order["_id"]}, {"$set": {"status": "paid", "paid_at": datetime.utcnow(), "pushinpay_last": pp}}, return_document=ReturnDocument.AFTER)
                activate_user_plan(order["user_id"], order["plan"])
                status = "paid"
            else:
                db.orders.update_one({"_id": order["_id"]}, {"$set": {"pushinpay_last": pp}})
        except Exception:
            pass
        if status == "pending" and order.get("expires_at") and datetime.utcnow() > order["expires_at"]:
            db.orders.update_one({"_id": order["_id"]}, {"$set": {"status": "expired"}})
            status = "expired"
    return jsonify({"ok": True, "status": status})

@app.route('/api/pix/qr/<transaction_id>', methods=['GET'])
@login_required
def api_pix_qr(transaction_id):
    order = db.orders.find_one({"transaction_id": transaction_id, "user_id": safe_user_id()})
    pix_payload = order.get("pix_payload") if order else None
    if not pix_payload:
        try:
            pp = consult_pp(transaction_id)
            for k in ("qr_code", "payload", "pix", "copiacolapix", "pix_string"):
                if k in pp and pp[k]:
                    pix_payload = str(pp[k])
                    break
            if not pix_payload:
                for k in ("qr_code_base64", "qr_base64", "qrcode_base64"):
                    if k in pp and pp[k]:
                        img_bytes = base64.b64decode(pp[k])
                        return send_file(io.BytesIO(img_bytes), mimetype="image/png", download_name=f"qr_{transaction_id}.png")
        except Exception:
            pass
    if not pix_payload:
        return abort(404)
    img = qr_png_from_payload(pix_payload)
    return send_file(img, mimetype="image/png", download_name=f"qr_{transaction_id}.png")

@app.route('/check/<transaction_id>', methods=['GET'])
@login_required
def check_transaction(transaction_id):
    try:
        resp = consult_pp(transaction_id)
    except requests.HTTPError as e:
        return jsonify({"error": "erro na API PushinPay", "detail": e.response.text}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    status = None
    if isinstance(resp, dict):
        for k in ("status", "state", "payment_status"):
            if k in resp:
                status = resp[k]
                break
    return jsonify({"status": status, "raw": resp})

def verify_sig(raw_body, header_signature, secret):
    if not secret or not header_signature:
        return False
    computed = hmac.new(secret.encode("utf-8"), raw_body, digestmod=hashlib.sha256).digest()
    try:
        hdr = header_signature.strip()
        if hdr.startswith("sha256="):
            hdr = hdr.split("=", 1)[1]
        try:
            hb = base64.b64decode(hdr)
            if hmac.compare_digest(hb, computed):
                return True
        except Exception:
            pass
        try:
            hx = hdr.replace("0x", "")
            hb2 = bytes.fromhex(hx)
            if hmac.compare_digest(hb2, computed):
                return True
        except Exception:
            pass
    except Exception:
        pass
    return False

@app.route('/api/pushinpay/webhook', methods=['POST'])
def pushinpay_webhook():
    raw = request.get_data()
    sig = request.headers.get("X-Pushinpay-Signature") or request.headers.get("X-Signature") or request.headers.get("Signature") or request.headers.get("Authorization")
    verified = verify_sig(raw, sig, WEBHOOK_SECRET) if WEBHOOK_SECRET else False
    try:
        payload = request.get_json(force=True, silent=True) or {}
    except Exception:
        payload = {}
    tid = payload.get("transaction_id") or payload.get("id") or payload.get("txid")
    st = (payload.get("status") or payload.get("state") or payload.get("payment_status") or "").lower()
    if tid and st in ("paid", "pago", "success", "confirmed"):
        ok_to_mark = verified
        if not ok_to_mark:
            try:
                pp = consult_pp(tid)
                st2 = str(pp.get("status", "")).lower()
                if st2 in ("paid", "pago", "success", "confirmed"):
                    ok_to_mark = True
            except Exception:
                ok_to_mark = False
        if ok_to_mark:
            order = db.orders.find_one_and_update({"transaction_id": str(tid)}, {"$set": {"status": "paid", "paid_at": datetime.utcnow(), "webhook_last": payload, "webhook_verified": verified}}, return_document=ReturnDocument.AFTER)
            if order:
                try:
                    activate_user_plan(order["user_id"], order["plan"])
                except Exception:
                    pass
    return jsonify({"ok": True, "verified": verified})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
