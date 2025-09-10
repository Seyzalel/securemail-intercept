import os
import io
import csv
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus

import requests
from flask import Blueprint, render_template, request, jsonify, session, abort, send_file
from pymongo import MongoClient, ASCENDING, DESCENDING, ReturnDocument

admin_bp = Blueprint("admin", __name__, url_prefix="/superadmin", template_folder=".")

USER = quote_plus(os.environ.get("DB_USER", "seyzalel_db_user"))
PWD = quote_plus(os.environ.get("DB_PASS", "pAd1F4iscPwdyRvV"))
MONGO_URI = f"mongodb+srv://{USER}:{PWD}@securemail.r9xmnzl.mongodb.net/?retryWrites=true&w=majority&appName=SecureMail"
client = MongoClient(MONGO_URI)
db = client["securemail"]

PUSHINPAY_TOKEN = os.environ.get("PUSHINPAY_TOKEN", "45911|0CnwU402QB1Zw1w15Lf69cDyQZtPd0RovG2TLjgQce6b6af1")
PUSHINPAY_BASE_URL = "https://api.pushinpay.com.br"
HEADERS_PP = {"Authorization": f"Bearer {PUSHINPAY_TOKEN}", "Accept": "application/json", "Content-Type": "application/json"}

PLANS = {
    "basic-15": {"key": "basic-15", "name": "Básico", "price_cents": 3500, "price_display": "R$35", "period": "15 dias", "duration_days": 15, "limit_per_day": 5, "support": "WhatsApp", "lifetime": False},
    "standard-30": {"key": "standard-30", "name": "Padrão", "price_cents": 5000, "price_display": "R$50", "period": "30 dias", "duration_days": 30, "limit_per_day": 10, "support": "WhatsApp prioritário", "lifetime": False},
    "advanced-30": {"key": "advanced-30", "name": "Avançado", "price_cents": 9700, "price_display": "R$97", "period": "30 dias", "duration_days": 30, "limit_per_day": 25, "support": "WhatsApp 24/7 prioritário", "lifetime": False},
    "lifetime": {"key": "lifetime", "name": "Vitalício", "price_cents": 13900, "price_display": "R$139", "period": "vitalício", "duration_days": None, "limit_per_day": 20, "support": "WhatsApp 24/7 prioritário", "lifetime": True},
}
PLAN_CODES = {0: None, 1: "basic-15", 2: "standard-30", 3: "advanced-30", 4: "lifetime"}
CODE_BY_KEY = {"basic-15": 1, "standard-30": 2, "advanced-30": 3, "lifetime": 4}

def plan_key_from_code(code):
    try:
        c = int(code)
    except Exception:
        c = 0
    return PLAN_CODES.get(c)

def plan_code_from_key(key):
    return CODE_BY_KEY.get(key, 0)

def brl_display(cents):
    v = (cents or 0) / 100.0
    s = f"{v:,.2f}"
    s = s.replace(",", "X").replace(".", ",").replace("X", ".")
    return f"R${s}"

def now_utc():
    return datetime.utcnow()

def parse_dt(s):
    if not s:
        return None
    try:
        t = s.strip()
        if t.endswith("Z"):
            t = t[:-1] + "+00:00"
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None

def iso_or_none(v):
    if isinstance(v, datetime):
        try:
            return v.isoformat()
        except Exception:
            return str(v)
    return v if v is not None else ""

def admin_required(fn):
    def _wrap(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            abort(403)
        u = db.users.find_one({"_id": uid})
        if not u or str(u.get("admin") or "no").lower() != "yes":
            abort(403)
        return fn(*args, **kwargs)
    _wrap.__name__ = fn.__name__
    return _wrap

def activate_user_plan(user_id, plan_key, extend=False):
    now = now_utc()
    info = PLANS.get(plan_key)
    if not info:
        return False
    expires_at = None
    if not info["lifetime"]:
        base = now
        u = db.users.find_one({"_id": user_id}) or {}
        pdoc = u.get("plan") or {}
        cur = pdoc.get("expires_at")
        if extend and cur and isinstance(cur, datetime) and cur > now:
            base = cur
        expires_at = base + timedelta(days=int(info["duration_days"] or 0))
    payload = {
        "plan": {
            "key": info["key"],
            "name": info["name"],
            "activated_at": now,
            "expires_at": expires_at,
            "limit_per_day": info["limit_per_day"],
            "support": info["support"],
            "period": info["period"],
            "lifetime": info["lifetime"],
        },
        "plan_code": plan_code_from_key(info["key"]),
    }
    db.users.update_one({"_id": user_id}, {"$set": payload})
    return True

def deactivate_user_plan(user_id):
    db.users.update_one({"_id": user_id}, {"$set": {"plan": None, "plan_code": 0}})
    return True

def consult_pp(transaction_id):
    url = f"{PUSHINPAY_BASE_URL}/api/transactions/{transaction_id}"
    r = requests.get(url, headers=HEADERS_PP, timeout=12)
    r.raise_for_status()
    return r.json()

def revenue_sum(filter_q):
    total = 0
    cur = db.orders.find(filter_q, {"plan.price_cents": 1})
    for o in cur:
        p = ((o.get("plan") or {}).get("price_cents") or 0)
        total += int(p)
    return total

@admin_bp.route("/", methods=["GET"])
@admin_required
def admin_home():
    return render_template("admin_panel.html")

@admin_bp.route("/api/metrics/revenue", methods=["GET"])
@admin_required
def metrics_revenue():
    now = now_utc()
    s7 = now - timedelta(days=7)
    s30 = now - timedelta(days=30)
    q_all = {"status": "paid"}
    q_7 = {"status": "paid", "paid_at": {"$gte": s7}}
    q_30 = {"status": "paid", "paid_at": {"$gte": s30}}
    all_time = revenue_sum(q_all)
    last_7d = revenue_sum(q_7)
    last_30d = revenue_sum(q_30)
    return jsonify({"ok": True, "currency": "BRL", "cents": {"all_time": all_time, "last_7d": last_7d, "last_30d": last_30d}, "display": {"all_time": brl_display(all_time), "last_7d": brl_display(last_7d), "last_30d": brl_display(last_30d)}})

@admin_bp.route("/api/users", methods=["GET"])
@admin_required
def list_users():
    q = (request.args.get("q") or "").strip()
    admin_flag = request.args.get("admin")
    active = request.args.get("active")
    page = max(1, int(request.args.get("page") or 1))
    size = max(1, min(200, int(request.args.get("size") or 25)))
    clauses = []
    if q:
        qq = q
        ql = q.lower()
        clauses.append({"$or": [
            {"username": {"$regex": qq, "$options": "i"}},
            {"email": {"$regex": qq, "$options": "i"}},
            {"username_lower": {"$regex": ql, "$options": "i"}},
            {"email_lower": {"$regex": ql, "$options": "i"}},
        ]})
    if admin_flag in ("yes", "no"):
        clauses.append({"admin": admin_flag})
    if active in ("true", "false"):
        now = now_utc()
        if active == "true":
            clauses.append({"$or": [
                {"plan.lifetime": True},
                {"plan.expires_at": None},
                {"plan.expires_at": {"$gt": now}},
            ]})
        else:
            clauses.append({"$or": [
                {"plan": None},
                {"plan.expires_at": {"$lte": now}},
            ]})
    filt = {"$and": clauses} if clauses else {}
    total = db.users.count_documents(filt)
    cur = db.users.find(filt).sort([("created_at", DESCENDING)]).skip((page - 1) * size).limit(size)
    items = []
    for u in cur:
        plan = u.get("plan") or {}
        items.append({
            "id": u.get("_id"),
            "username": u.get("username"),
            "email": u.get("email"),
            "admin": u.get("admin", "no"),
            "created_at": u.get("created_at"),
            "last_login_at": u.get("last_login_at"),
            "plan_code": int(u.get("plan_code") or 0),
            "plan": {
                "key": plan.get("key"),
                "name": plan.get("name"),
                "activated_at": plan.get("activated_at"),
                "expires_at": plan.get("expires_at"),
                "limit_per_day": plan.get("limit_per_day"),
                "support": plan.get("support"),
                "period": plan.get("period"),
                "lifetime": plan.get("lifetime"),
            },
            "suspended": bool(u.get("suspended") or False),
        })
    return jsonify({"ok": True, "page": page, "size": size, "total": total, "items": items})

@admin_bp.route("/api/users/<user_id>/plan", methods=["POST"])
@admin_required
def change_user_plan(user_id):
    data = request.get_json(force=True, silent=True) or {}
    plan_key = data.get("plan_key")
    plan_code = data.get("plan_code")
    extend = bool(data.get("extend") or False)
    if not plan_key and plan_code is not None:
        plan_key = plan_key_from_code(plan_code)
    if not plan_key or plan_key not in PLANS:
        return jsonify({"ok": False, "error": "Plano inválido."}), 400
    ok = activate_user_plan(user_id, plan_key, extend=extend)
    if not ok:
        return jsonify({"ok": False, "error": "Falha ao ativar plano."}), 500
    u = db.users.find_one({"_id": user_id})
    log_admin("user.plan.set", session.get("user_id"), target=user_id, payload={"plan_key": plan_key, "extend": extend}, result={"plan_code": u.get("plan_code")})
    return jsonify({"ok": True, "user": {"id": user_id, "plan_code": u.get("plan_code"), "plan": u.get("plan")}})

@admin_bp.route("/api/users/<user_id>/deactivate", methods=["POST"])
@admin_required
def deactivate_plan(user_id):
    deactivate_user_plan(user_id)
    u = db.users.find_one({"_id": user_id})
    log_admin("user.plan.deactivate", session.get("user_id"), target=user_id)
    return jsonify({"ok": True, "user": {"id": user_id, "plan_code": u.get("plan_code"), "plan": u.get("plan")}})

@admin_bp.route("/api/users/<user_id>/usage/reset", methods=["POST"])
@admin_required
def reset_usage(user_id):
    today = now_utc().date().isoformat()
    db.usage.update_one({"user_id": user_id, "date": today}, {"$set": {"count": 0}}, upsert=True)
    doc = db.usage.find_one({"user_id": user_id, "date": today}) or {"count": 0}
    log_admin("user.usage.reset", session.get("user_id"), target=user_id, result={"date": today, "used": doc.get("count", 0)})
    return jsonify({"ok": True, "user_id": user_id, "date": today, "used": doc.get("count", 0)})

@admin_bp.route("/api/users/<user_id>/admin-flag", methods=["POST"])
@admin_required
def set_admin_flag(user_id):
    data = request.get_json(force=True, silent=True) or {}
    val = str(data.get("value") or "no").lower()
    if val not in ("yes", "no"):
        return jsonify({"ok": False, "error": "Valor inválido."}), 400
    db.users.update_one({"_id": user_id}, {"$set": {"admin": val}})
    u = db.users.find_one({"_id": user_id})
    log_admin("user.admin.flag", session.get("user_id"), target=user_id, payload={"value": val})
    return jsonify({"ok": True, "user": {"id": user_id, "admin": u.get("admin", "no")}})

@admin_bp.route("/api/users/<user_id>/logout", methods=["POST"])
@admin_required
def force_logout_user(user_id):
    now = now_utc()
    db.users.update_one({"_id": user_id}, {"$set": {"session_revoked_at": now}, "$inc": {"session_version": 1}})
    log_admin("user.logout.force", session.get("user_id"), target=user_id, result={"revoked_at": now})
    return jsonify({"ok": True, "user_id": user_id, "revoked_at": now})

@admin_bp.route("/api/users/<user_id>/suspend", methods=["POST"])
@admin_required
def suspend_user(user_id):
    now = now_utc()
    db.users.update_one({"_id": user_id}, {"$set": {"suspended": True, "suspended_at": now}})
    log_admin("user.suspend", session.get("user_id"), target=user_id, result={"suspended": True})
    return jsonify({"ok": True, "user_id": user_id, "suspended": True, "suspended_at": now})

@admin_bp.route("/api/users/<user_id>/unsuspend", methods=["POST"])
@admin_required
def unsuspend_user(user_id):
    db.users.update_one({"_id": user_id}, {"$set": {"suspended": False}, "$unset": {"suspended_at": ""}})
    log_admin("user.unsuspend", session.get("user_id"), target=user_id, result={"suspended": False})
    return jsonify({"ok": True, "user_id": user_id, "suspended": False})

@admin_bp.route("/api/users/<user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    u = db.users.find_one({"_id": user_id})
    if not u:
        return jsonify({"ok": False, "error": "Usuário não encontrado."}), 404
    db.orders.update_many({"user_id": user_id}, {"$set": {"user_deleted": True}})
    db.usage.delete_many({"user_id": user_id})
    db.users.delete_one({"_id": user_id})
    log_admin("user.delete", session.get("user_id"), target=user_id)
    return jsonify({"ok": True, "deleted_user_id": user_id})

@admin_bp.route("/api/transactions", methods=["GET"])
@admin_required
def list_transactions():
    q = (request.args.get("q") or "").strip()
    status = request.args.get("status")
    date_from = request.args.get("from")
    date_to = request.args.get("to")
    page = max(1, int(request.args.get("page") or 1))
    size = max(1, min(200, int(request.args.get("size") or 25)))
    filt = {}
    if q:
        filt["$or"] = [
            {"transaction_id": {"$regex": q, "$options": "i"}},
            {"username": {"$regex": q, "$options": "i"}},
            {"plan.name": {"$regex": q, "$options": "i"}},
            {"fullname": {"$regex": q, "$options": "i"}},
            {"cpf": {"$regex": q, "$options": "i"}},
        ]
    if status:
        filt["status"] = status
    if date_from or date_to:
        rng = {}
        df = parse_dt(date_from)
        dt = parse_dt(date_to)
        if df:
            rng["$gte"] = df
        if dt:
            rng["$lte"] = dt
        if rng:
            filt["created_at"] = rng
    total = db.orders.count_documents(filt)
    cur = db.orders.find(filt).sort([("created_at", DESCENDING)]).skip((page - 1) * size).limit(size)
    items = []
    for o in cur:
        items.append({
            "id": o.get("_id"),
            "user_id": o.get("user_id"),
            "username": o.get("username"),
            "transaction_id": o.get("transaction_id"),
            "status": o.get("status"),
            "created_at": o.get("created_at"),
            "paid_at": o.get("paid_at"),
            "plan": o.get("plan"),
            "price_cents": ((o.get("plan") or {}).get("price_cents") or 0),
            "user_deleted": bool(o.get("user_deleted") or False),
        })
    return jsonify({"ok": True, "page": page, "size": size, "total": total, "items": items})

@admin_bp.route("/api/transactions/<tid>", methods=["GET"])
@admin_required
def transaction_detail(tid):
    refresh = str(request.args.get("refresh") or "0") in ("1", "true", "yes")
    o = db.orders.find_one({"transaction_id": tid})
    if not o:
        return jsonify({"ok": False, "error": "Transação não encontrada."}), 404
    live = None
    if refresh:
        try:
            live = consult_pp(tid)
            db.orders.update_one({"_id": o["_id"]}, {"$set": {"pushinpay_last": live, "pushinpay_last_refreshed_at": now_utc()}})
            o = db.orders.find_one({"_id": o["_id"]})
        except Exception:
            live = None
    return jsonify({"ok": True, "order": o, "live": live})

@admin_bp.route("/api/transactions/<tid>/status", methods=["POST"])
@admin_required
def transaction_set_status(tid):
    data = request.get_json(force=True, silent=True) or {}
    target = str(data.get("status") or "").lower()
    if target not in ("pending", "paid", "expired", "refunded", "canceled", "cancelled"):
        return jsonify({"ok": False, "error": "Status inválido."}), 400
    o = db.orders.find_one({"transaction_id": tid})
    if not o:
        return jsonify({"ok": False, "error": "Transação não encontrada."}), 404
    up = {"status": target}
    if target == "paid":
        up["paid_at"] = now_utc()
    res = db.orders.find_one_and_update({"_id": o["_id"]}, {"$set": up}, return_document=ReturnDocument.AFTER)
    if target == "paid":
        p = (o.get("plan") or {})
        activate_user_plan(o.get("user_id"), p.get("key"), extend=False)
    if target in ("refunded", "canceled", "cancelled"):
        deactivate_user_plan(o.get("user_id"))
    log_admin("transaction.status.set", session.get("user_id"), target=tid, payload={"status": target})
    return jsonify({"ok": True, "order": res})

@admin_bp.route("/api/transactions/<tid>/receipt", methods=["GET"])
@admin_required
def transaction_receipt(tid):
    o = db.orders.find_one({"transaction_id": tid})
    if not o:
        return jsonify({"ok": False, "error": "Transação não encontrada."}), 404
    if str(o.get("status") or "").lower() != "paid":
        return jsonify({"ok": False, "error": "Transação não está paga."}), 400
    u = db.users.find_one({"_id": o.get("user_id")}) or {}
    proof = {
        "ok": True,
        "transaction_id": o.get("transaction_id"),
        "status": o.get("status"),
        "created_at": o.get("created_at"),
        "paid_at": o.get("paid_at"),
        "webhook_verified": bool(o.get("webhook_verified") or False),
        "user": {
            "id": u.get("_id"),
            "username": u.get("username"),
            "email": u.get("email"),
            "fullname": o.get("fullname"),
            "cpf": o.get("cpf"),
        },
        "plan": {
            "key": (o.get("plan") or {}).get("key"),
            "name": (o.get("plan") or {}).get("name"),
            "period": (o.get("plan") or {}).get("period"),
            "limit_per_day": (o.get("plan") or {}).get("limit_per_day"),
            "support": (o.get("plan") or {}).get("support"),
            "price_cents": (o.get("plan") or {}).get("price_cents"),
            "price_display": (o.get("plan") or {}).get("price_display"),
        },
        "amount_cents": ((o.get("plan") or {}).get("price_cents") or 0),
        "amount_display": brl_display(((o.get("plan") or {}).get("price_cents") or 0)),
        "pushinpay_response": o.get("pushinpay_response"),
        "pushinpay_last": o.get("pushinpay_last"),
        "webhook_last": o.get("webhook_last"),
        "service_delivery": {
            "plan_activated": True if (db.users.find_one({"_id": o.get("user_id")}) or {}).get("plan") else False,
            "plan_snapshot": (db.users.find_one({"_id": o.get("user_id")}) or {}).get("plan"),
        },
    }
    return jsonify(proof)

def safe_csv_cell(s):
    if s is None:
        return ""
    x = str(s)
    if x[:1] in ("=", "+", "-", "@"):
        return "'" + x
    return x

@admin_bp.route("/api/export/transactions.csv", methods=["GET"])
@admin_required
def export_transactions_csv():
    q = (request.args.get("q") or "").strip()
    status = request.args.get("status")
    date_from = request.args.get("from")
    date_to = request.args.get("to")
    filt = {}
    if q:
        filt["$or"] = [
            {"transaction_id": {"$regex": q, "$options": "i"}},
            {"username": {"$regex": q, "$options": "i"}},
            {"plan.name": {"$regex": q, "$options": "i"}},
            {"fullname": {"$regex": q, "$options": "i"}},
            {"cpf": {"$regex": q, "$options": "i"}},
        ]
    if status:
        filt["status"] = status
    if date_from or date_to:
        rng = {}
        df = parse_dt(date_from)
        dt = parse_dt(date_to)
        if df:
            rng["$gte"] = df
        if dt:
            rng["$lte"] = dt
        if rng:
            filt["created_at"] = rng
    cur = db.orders.find(filt).sort([("created_at", DESCENDING)])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["transaction_id", "status", "username", "user_id", "fullname", "cpf", "plan_key", "plan_name", "price_cents", "created_at", "paid_at"])
    for o in cur:
        p = o.get("plan") or {}
        writer.writerow([
            safe_csv_cell(o.get("transaction_id")),
            safe_csv_cell(o.get("status")),
            safe_csv_cell(o.get("username")),
            safe_csv_cell(o.get("user_id")),
            safe_csv_cell(o.get("fullname")),
            safe_csv_cell(o.get("cpf")),
            safe_csv_cell(p.get("key")),
            safe_csv_cell(p.get("name")),
            safe_csv_cell(p.get("price_cents")),
            safe_csv_cell(iso_or_none(o.get("created_at"))),
            safe_csv_cell(iso_or_none(o.get("paid_at"))),
        ])
    mem = io.BytesIO()
    mem.write("\ufeff".encode("utf-8"))
    mem.write(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv; charset=utf-8", as_attachment=True, download_name="transactions.csv")

@admin_bp.route("/api/export/users.csv", methods=["GET"])
@admin_required
def export_users_csv():
    q = (request.args.get("q") or "").strip()
    admin_flag = request.args.get("admin")
    clauses = []
    if q:
        qq = q
        ql = q.lower()
        clauses.append({"$or": [
            {"username": {"$regex": qq, "$options": "i"}},
            {"email": {"$regex": qq, "$options": "i"}},
            {"username_lower": {"$regex": ql, "$options": "i"}},
            {"email_lower": {"$regex": ql, "$options": "i"}},
        ]})
    if admin_flag in ("yes", "no"):
        clauses.append({"admin": admin_flag})
    filt = {"$and": clauses} if clauses else {}
    cur = db.users.find(filt).sort([("created_at", DESCENDING)])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "username", "email", "admin", "created_at", "last_login_at", "plan_code", "plan_key", "plan_name", "expires_at", "suspended"])
    for u in cur:
        p = u.get("plan") or {}
        writer.writerow([
            safe_csv_cell(u.get("_id")),
            safe_csv_cell(u.get("username")),
            safe_csv_cell(u.get("email")),
            safe_csv_cell(u.get("admin", "no")),
            safe_csv_cell(iso_or_none(u.get("created_at"))),
            safe_csv_cell(iso_or_none(u.get("last_login_at"))),
            safe_csv_cell(int(u.get("plan_code") or 0)),
            safe_csv_cell(p.get("key")),
            safe_csv_cell(p.get("name")),
            safe_csv_cell(iso_or_none(p.get("expires_at"))),
            safe_csv_cell(bool(u.get("suspended") or False)),
        ])
    mem = io.BytesIO()
    mem.write("\ufeff".encode("utf-8"))
    mem.write(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv; charset=utf-8", as_attachment=True, download_name="users.csv")

@admin_bp.route("/api/audit", methods=["GET"])
@admin_required
def list_audit():
    page = max(1, int(request.args.get("page") or 1))
    size = max(1, min(200, int(request.args.get("size") or 50)))
    total = db.admin_logs.count_documents({})
    cur = db.admin_logs.find({}).sort([("created_at", DESCENDING)]).skip((page - 1) * size).limit(size)
    items = list(cur)
    return jsonify({"ok": True, "page": page, "size": size, "total": total, "items": items})

@admin_bp.route("/api/config/engineering", methods=["GET"])
@admin_required
def get_config_engineering():
    doc = db.config.find_one({"_id": "engineering"}) or {}
    data = {"username": doc.get("username"), "link": doc.get("link"), "updated_at": doc.get("updated_at")}
    return jsonify({"ok": True, "data": data})

@admin_bp.route("/api/config/engineering", methods=["POST"])
@admin_required
def set_config_engineering():
    data = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username") or "").strip()
    link = str(data.get("link") or "").strip()
    up = {"username": username, "link": link, "updated_at": now_utc()}
    db.config.update_one({"_id": "engineering"}, {"$set": up}, upsert=True)
    log_admin("config.engineering.update", session.get("user_id"), target="engineering", payload={"username": username, "link": link})
    return jsonify({"ok": True})

def log_admin(action, actor_id, target=None, payload=None, result=None):
    try:
        db.admin_logs.insert_one({"action": action, "actor_id": actor_id, "target": target, "payload": payload, "result": result, "created_at": now_utc()})
    except Exception:
        pass

@admin_bp.after_request
def add_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp
