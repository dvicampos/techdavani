from flask import (
    Flask, request, render_template, redirect, url_for, flash,
    send_from_directory, render_template_string, Response, send_file, current_app
)
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from datetime import datetime, date, timedelta
from bson.objectid import ObjectId
from functools import wraps
from jinja2 import TemplateNotFound
from urllib.parse import urlparse
from io import BytesIO
from pymongo import ReturnDocument

import os
import re
import requests
import qrcode

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.pdfmetrics import stringWidth
from urllib.parse import quote_plus

load_dotenv()
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")



def slugify(text):
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s-]', '', text)
    return re.sub(r'[\s\-]+', '-', text).strip('-')


UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'pdf', 'doc', 'docx'}

load_dotenv()

app = Flask(__name__)
# === Paths seguros para Render ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Si tienes un Disk en Render, define UPLOAD_DIR en el panel (p.ej. /var/data/uploads)
UPLOAD_DIR = os.getenv("UPLOAD_DIR")

# Fallback temporal (no persistente) si no hay Disk configurado:
if not UPLOAD_DIR:
    UPLOAD_DIR = "/tmp/uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MONGO_URI'] = os.getenv('MONGO_URI')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # nombre de la función login

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('SECRET_KEY') 

mongo = PyMongo(app)
try:
    mongo.db.appointments.create_index([("page_id", 1), ("start_at", 1)], name="appt_page_start_idx")
    mongo.db.appointments.create_index([("page_id", 1), ("status", 1)], name="appt_page_status_idx")
    mongo.db.booking_exceptions.create_index([("page_id", 1), ("date", 1)], unique=True, name="ex_page_date_unique")
except Exception as e:
    app.logger.warning(f"Index booking error: {e}")

try:
    mongo.db.productos.create_index([("page_id", 1), ("sku", 1)], name="prod_page_sku_idx")
    mongo.db.productos.create_index([("page_id", 1), ("barcode", 1)], name="prod_page_barcode_idx")
    mongo.db.ventas.create_index([("page_id", 1), ("created_at", -1)], name="sales_page_created_idx")
    mongo.db.ventas.create_index([("page_id", 1), ("folio", 1)], unique=True, name="sales_page_folio_unique_idx")
    mongo.db.counters.create_index([("_id", 1)], unique=True, name="counter_id_unique_idx")
except Exception as e:
    app.logger.warning(f"Index POS error: {e}")

mail = Mail(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@login_manager.unauthorized_handler
def unauthorized_callback():
    flash("Debes iniciar sesión para acceder a esta página.")
    return redirect(url_for('login'))

# --- User model (reemplazar tu clase User por esta) ---
class User(UserMixin):
    def __init__(self, user_data):
        self._id = str(user_data['_id'])
        self.email = user_data['email']
        self.nombre = user_data['nombre']
        self.password = user_data['password']
        self.role = user_data.get('role', 'admin')
        # legacy:
        self.page_id_legacy = user_data.get('page_id')
        # nuevo:
        self.page_ids = user_data.get('page_ids', [])
        self.current_page_id = user_data.get('current_page_id') or user_data.get('page_id')

    @property
    def id(self):
        return self._id

from flask import session

def get_current_page_id():
    if not current_user.is_authenticated:
        return None

    def as_oid(v):
        try:
            return ObjectId(str(v))
        except Exception:
            return None

    # prioridad: session -> user.current_page_id -> user.page_id (legacy)
    sid = session.get('current_page_id')
    if sid:
        oid = as_oid(sid)
        if oid:
            return oid

    u = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    if not u:
        return None

    if u.get('current_page_id'):
        oid = as_oid(u['current_page_id'])
        if oid:
            return oid
    if u.get('page_id'):
        oid = as_oid(u['page_id'])
        if oid:
            return oid
    # último recurso: primer page_ids
    for pid in (u.get('page_ids') or []):
        oid = as_oid(pid)
        if oid:
            return oid
    return None

def set_current_page_id(page_id, user_id: str | None = None):
    """
    Guarda el sitio actual en sesión SIEMPRE.
    Y si hay user autenticado (o se pasa user_id), también lo guarda en BD.
    """
    session['current_page_id'] = str(page_id)

    # Si no hay user autenticado, ya con sesión estamos bien
    uid = user_id
    if not uid and getattr(current_user, "is_authenticated", False):
        uid = current_user.id

    if not uid:
        return  # anónimo, no hay nada que actualizar en users

    try:
        mongo.db.users.update_one(
            {'_id': ObjectId(str(uid))},
            {'$set': {'current_page_id': ObjectId(str(page_id))}}
        )
    except Exception as e:
        app.logger.warning(f"set_current_page_id error: {e}")

def ensure_user_page_lists(user_id, page_id: ObjectId):
    u = mongo.db.users.find_one({'_id': ObjectId(str(user_id))})
    if not u:
        return

    updates = {}
    page_ids = list(u.get('page_ids', []))

    # normaliza page_ids a ObjectId
    norm = []
    for x in page_ids:
        try:
            norm.append(ObjectId(str(x)))
        except:
            pass
    page_ids = norm

    if ObjectId(str(page_id)) not in page_ids:
        page_ids.append(ObjectId(str(page_id)))
        updates['page_ids'] = page_ids

    if not u.get('current_page_id'):
        updates['current_page_id'] = ObjectId(str(page_id))

    if updates:
        mongo.db.users.update_one({'_id': ObjectId(str(user_id))}, {'$set': updates})

     
from pymongo import ASCENDING

def unique_slug_for_page(base_text: str) -> str:
    base = slugify(base_text) or "sitio"
    slug = base
    n = 2
    while mongo.db.page_data.count_documents({"slug": slug}) > 0:
        slug = f"{base}-{n}"
        n += 1
    return slug

# índice único para que no haya choques (se crea 1 sola vez)
try:
    mongo.db.page_data.create_index([("slug", ASCENDING)], unique=True, name="slug_unique_idx")
except Exception as e:
    print("Index slug_unique_idx:", e)

def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('No tienes permiso para acceder aquí.')
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

def require_active_subscription(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))

        # ✅ BYPASS ADMIN DEMO (no depende de MP ni trial)
        # 1) Por ENV (súper seguro)
        if is_demo_admin(current_user.id):
            return fn(*args, **kwargs)

        # 2) Opcional: override guardado en Mongo (también útil)
        if user_has_subscription_override(current_user.id):
            return fn(*args, **kwargs)

        page_id = get_current_page_id()
        if not page_id:
            flash('Crea o selecciona un sitio para continuar.')
            return redirect(url_for('create_page'))

        # Backfill trial si tu página es vieja
        ensure_trial_on_page(page_id)

        # ✅ 1) Si tiene suscripción activa: OK
        if site_has_active_subscription(page_id):
            return fn(*args, **kwargs)

        # ✅ 2) Si trial activo: OK
        info = site_trial_info(page_id)
        if info["active"]:
            return fn(*args, **kwargs)

        # ❌ 3) No pago y trial expiró
        if info["trial_until"]:
            flash('⏳ Tu prueba gratis expiró. Activa tu suscripción para continuar.', 'warning')
        else:
            flash('Activa tu suscripción mensual para continuar.', 'warning')

        return redirect(url_for('billing_portal'))
    return wrapper

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def get_trial_days() -> int:
    try:
        return int(os.getenv("TRIAL_DAYS", "7"))
    except Exception:
        return 7

def site_trial_info(page_id: ObjectId) -> dict:
    """
    return:
      {
        "active": bool,
        "trial_until": datetime|None,
        "days_left": int|None
      }
    """
    page = mongo.db.page_data.find_one(
        {"_id": ObjectId(page_id)},
        {"trial_until": 1, "plan": 1}
    )
    if not page:
        return {"active": False, "trial_until": None, "days_left": None}

    tu = page.get("trial_until")
    if tu and isinstance(tu, datetime):
        now = datetime.utcnow()
        active = now <= tu
        seconds_left = max((tu - now).total_seconds(), 0)
        days_left = int((seconds_left + 86400 - 1) // 86400)  # ceil a días
        return {"active": active, "trial_until": tu, "days_left": days_left}

    return {"active": False, "trial_until": None, "days_left": None}

def ensure_trial_on_page(page_id: ObjectId):
    """
    Backfill para páginas viejas: si no tienen trial_until, se les asigna.
    """
    page = mongo.db.page_data.find_one({"_id": ObjectId(page_id)}, {"trial_until": 1, "plan": 1})
    if not page:
        return

    if not page.get("trial_until"):
        tu = datetime.utcnow() + timedelta(days=get_trial_days())
        mongo.db.page_data.update_one(
            {"_id": ObjectId(page_id)},
            {"$set": {"trial_until": tu, "plan": "trial"}}
        )

@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

def has_role(role):
    return current_user.role == role

# helpers de “licencia / addons”
def page_has_purchase(page_id, addon_slug):
    return mongo.db.purchases.count_documents({
        "page_id": ObjectId(page_id),
        "addon_slug": addon_slug,
        "status": "approved"
    }) > 0

def set_page_license_lifetime(page_id):
    mongo.db.page_data.update_one(
        {"_id": ObjectId(page_id)},
        {"$set": {"license": "lifetime", "license_activated_at": datetime.utcnow()}}
    )

def require_lifetime(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
        if not user or not user.get('page_id'):
            return redirect(url_for('create_page'))
        page_id = user['page_id']
        if not page_has_purchase(page_id, "lifetime"):
            flash('Activa tu licencia de por vida para continuar.')
            return redirect(url_for('pay_lifetime', page_id=str(page_id)))
        return fn(*args, **kwargs)
    return wrapper

def site_has_active_subscription(page_id: ObjectId):
    sub = mongo.db.subscriptions.find_one({
        "page_id": page_id,
        "status": {"$in": ["authorized", "active", "charged"]}  # estados “vivos”
    })
    return bool(sub)

def require_subscription_or_lifetime(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        page_id = get_current_page_id()
        if not page_id:
            flash('Crea o selecciona un sitio para continuar.')
            return redirect(url_for('create_page'))

        has_life = page_has_purchase(str(page_id), "lifetime")
        has_subs = site_has_active_subscription(page_id)

        if not (has_life or has_subs):
            flash('Activa tu suscripción mensual o la licencia de por vida.')
            return redirect(url_for('billing_portal'))  # ver ruta abajo
        return fn(*args, **kwargs)
    return wrapper

from datetime import date

def get_env_bool(name, default='false'):
    return os.getenv(name, default).strip().lower() == 'true'

def compute_coupon_price():
    price = float(os.getenv('LIFETIME_PRICE', '5490'))

    coupon_active = get_env_bool('COUPON_ACTIVE', 'false')
    code = os.getenv('COUPON_CODE', '').strip()
    dtype = (os.getenv('COUPON_DISCOUNT_TYPE', 'percent') or 'percent').strip().lower()
    value = float(os.getenv('COUPON_VALUE', '0') or 0)
    expiry_raw = os.getenv('COUPON_EXPIRY', '').strip()

    # Validación de fecha (si viene)
    valid_by_date = True
    if expiry_raw:
        try:
            y, m, d = [int(x) for x in expiry_raw.split('-')]
            valid_by_date = date.today() <= date(y, m, d)
        except Exception:
            valid_by_date = True  # si está mal la fecha, no bloqueamos

    show_coupon = coupon_active and code and value > 0 and valid_by_date

    discount_amount = 0.0
    if show_coupon:
        if dtype == 'percent':
            discount_amount = round(price * (value / 100.0), 2)
        elif dtype == 'fixed':
            discount_amount = round(min(value, price), 2)

    final_price = round(max(price - discount_amount, 0), 2)

    return {
        "base_price": price,
        "show_coupon": show_coupon,
        "coupon": {
            "code": code,
            "type": dtype,            # "percent" o "fixed"
            "value": value,
            "discount_amount": discount_amount,
            "expiry": expiry_raw or None
        },
        "final_price": final_price
    }

from flask import g

def current_site(required=True):
    """Resuelve el sitio desde:
    1) kwargs['slug'] si la ruta lo trae → fija current_page_id
    2) session/current_user (get_current_page_id)
    Inyecta g.page, g.page_id, g.page_slug. Si required y no hay, redirige a /sites.
    """
    def deco(fn):
        @wraps(fn)
        def wrap(*args, **kwargs):
            page = None
            # 1) si la ruta tiene slug, úsalo como fuente de verdad
            slug = kwargs.get('slug')
            if slug:
                page = get_page_by_slug(slug)
                if page:
                    set_current_page_id(page['_id'])

            # 2) si no hubo slug o no existía, intenta por session/usuario
            if not page:
                pid = get_current_page_id()
                if pid:
                    page = mongo.db.page_data.find_one({'_id': pid})

            if required and not page:
                flash('Crea o selecciona un sitio para continuar.')
                return redirect(url_for('sites'))

            if page:
                page = ensure_page_has_slug(page)

            g.page = page
            g.page_id = page and page['_id']
            g.page_slug = page and page['slug']
            return fn(*args, **kwargs)
        return wrap
    return deco

@app.context_processor
def site_helpers():
    def url_for_site(endpoint, **params):
        """Atajo: agrega slug actual si el endpoint lo requiere."""
        slug = getattr(g, 'page_slug', None)
        if slug:
            params.setdefault('slug', slug)
        return url_for(endpoint, **params)

    return dict(
        current_page=lambda: getattr(g, 'page', None),
        url_for_site=url_for_site
    )

from datetime import datetime, timezone

def is_demo_admin(user_id: str) -> bool:
    """
    Admin bypass seguro por ENV:
    - DEMO_ADMIN_USER_IDS: lista de ObjectId separados por coma
      ejemplo: 65a...c1,66b...d2
    """
    raw = (os.getenv("DEMO_ADMIN_USER_IDS") or "").strip()
    if not raw:
        return False

    allowed = {x.strip() for x in raw.split(",") if x.strip()}
    return str(user_id) in allowed


def user_has_subscription_override(user_id: str) -> bool:
    """
    Override por campo en users:
      subscription_override: { active: true, until: ISO|None }
    """
    u = mongo.db.users.find_one(
        {"_id": ObjectId(str(user_id))},
        {"subscription_override": 1}
    ) or {}

    ov = u.get("subscription_override") or {}
    if not ov.get("active"):
        return False

    until = ov.get("until")
    if not until:
        return True

    # until como ISO string: "2099-01-01T00:00:00Z"
    try:
        dt = datetime.fromisoformat(str(until).replace("Z", "+00:00"))
        return dt > datetime.now(timezone.utc)
    except Exception:
        # si viene raro, mejor no bloquear
        return True

@app.route('/switch/slug/<slug>')
@login_required
def switch_site_slug(slug):
    page = get_page_by_slug(slug)
    if not page:
        flash('Sitio no encontrado.')
        return redirect(url_for('sites'))

    # valida pertenencia
    u = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    owned_ids = {str(x) for x in (u.get('page_ids') or [])}
    owned_ids.add(str(u.get('page_id') or ''))
    if str(page['_id']) not in owned_ids:
        flash('No puedes acceder a ese sitio.')
        return redirect(url_for('sites'))

    set_current_page_id(page['_id'])
    page = ensure_page_has_slug(page)
    return redirect(url_for('dashboard_slug', slug=page['slug']))

@app.context_processor
def inject_sites():
    pages, current = [], ""
    try:
        if getattr(current_user, "is_authenticated", False):
            u = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
            ids = set()
            def add(v):
                try:
                    if v: ids.add(ObjectId(str(v)))
                except: pass
            for pid in (u.get('page_ids') or []): add(pid)
            add(u.get('page_id'))  # legacy

            pages = list(mongo.db.page_data.find({'_id': {'$in': list(ids)}}))
            for p in pages:
                if not p.get('slug'):
                    mongo.db.page_data.update_one({'_id': p['_id']}, {'$set': {'slug': slugify(p.get('business_name','sitio'))}})
                    p['slug'] = slugify(p.get('business_name','sitio'))

            cid = get_current_page_id()
            current = str(cid) if cid else ""
    except Exception:
        pass
    return dict(pages=pages, current=current)

@app.route('/billing')
@login_required
def billing_portal():
    page_id = get_current_page_id()
    page = mongo.db.page_data.find_one({'_id': page_id}) if page_id else None
    sub = mongo.db.subscriptions.find_one({"page_id": page_id}) if page_id else None

    trial = {"active": False, "trial_until": None, "days_left": None}
    if page_id:
        ensure_trial_on_page(page_id)
        trial = site_trial_info(page_id)

    return render_template('billing.html', page=page, sub=sub, trial=trial)

MP_PREAPPROVALS_URL = "https://api.mercadopago.com/preapproval"

def get_env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return v.strip() if v is not None else default

def get_env_int(name: str, default: int = 0) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except Exception:
        return default

def get_env_float(name: str, default: float = 0.0) -> float:
    try:
        return float(os.getenv(name, str(default)).strip())
    except Exception:
        return default

def get_subscription_config():
    """Lee todos los datos del plan de suscripción desde .env."""
    return {
        "name": get_env_str("SUBSCRIPTION_NAME", "Suscripción Mensual MyPymes"),
        "price": get_env_float("SUBSCRIPTION_PRICE", 499.0),
        "currency": get_env_str("SUBSCRIPTION_CURRENCY", "MXN"),
        "frequency": get_env_int("SUBSCRIPTION_FREQUENCY", 1),
        "frequency_type": get_env_str("SUBSCRIPTION_FREQUENCY_TYPE", "months"),
        "success_url": get_env_str("MP_SUCCESS_URL", ""),   # fallback lo haremos abajo
        "failure_url": get_env_str("MP_FAILURE_URL", ""),
    }

@app.context_processor
def inject_subscription_plan():
    return dict(SUB_PLAN=get_subscription_config())

@app.route('/pay/subscription')
@login_required
def pay_subscription():
    import json, logging
    logging.basicConfig(level=logging.INFO)

    cfg = get_subscription_config()

    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio para continuar.')
        return redirect(url_for('billing_portal'))

    # Evitar duplicar si ya tiene lifetime o suscripción activa
    if page_has_purchase(str(page_id), "lifetime"):
        flash('Tu sitio ya tiene licencia de por vida activa.')
        return redirect(url_for('dashboard'))

    if site_has_active_subscription(page_id):
        flash('Tu suscripción ya está activa.')
        return redirect(url_for('dashboard'))

    # URLs de retorno
    back_url = cfg["success_url"] or url_for('billing_portal', _external=True)

    # Motivo que verá el usuario en MP
    reason = f'{cfg["name"]} — ${int(cfg["price"])} {cfg["currency"]}/mes'

    payload = {
        "reason": reason,
        "payer_email": current_user.email,   # 👈 recomendado por MP
        "auto_recurring": {
            "frequency": cfg["frequency"],
            "frequency_type": cfg["frequency_type"],  # "months" o "days"
            "transaction_amount": cfg["price"],
            "currency_id": cfg["currency"]
        },
        "back_url": back_url,
        "status": "pending",
        "external_reference": f"{current_user.id}|{str(page_id)}|subscription"
    }

    try:
        r = requests.post(
            MP_PREAPPROVALS_URL,
            headers=mp_headers(),
            json=payload,
            timeout=20
        )
        data = r.json() if r.headers.get('Content-Type','').startswith('application/json') else {}
        init_point = (
            data.get("init_point")
            or data.get("sandbox_init_point")
            or data.get("preapproval_url")
            or data.get("preapproval_link")
        )

        if r.status_code >= 400 or not init_point:
            logging.error("MP preapproval error %s: %s", r.status_code, data)
            msg = data.get("message") or "Respuesta inválida de Mercado Pago."
            cause = data.get("cause")
            if isinstance(cause, list) and cause:
                msg += f" ({cause[0].get('code')} - {cause[0].get('description')})"
            flash(f"No se pudo iniciar la suscripción: {msg}", "danger")
            return redirect(url_for('billing_portal'))

        mongo.db.subscriptions.update_one(
            {"page_id": page_id},
            {"$set": {
                "page_id": page_id,
                "user_id": ObjectId(current_user.id),
                "provider": "mercado_pago",
                "preapproval_id": data.get("id"),
                "status": data.get("status", "pending"),
                "raw": data,
                "last_event": datetime.utcnow()
            }},
            upsert=True
        )
        return redirect(init_point)

    except Exception as e:
        logging.exception("Excepción creando preapproval")
        flash(f"Error creando la suscripción: {e}", "danger")
        return redirect(url_for('billing_portal'))

@app.route('/mp/sub_webhook', methods=['POST', 'GET'])
def mp_sub_webhook():
    try:
        data = request.get_json(silent=True) or {}
        query = request.args.to_dict()

        pre_id = (
            data.get('id')
            or query.get('id')
            or (data.get('resource') or '').split('/')[-1]
        )

        if not pre_id:
            return "ignored", 200

        # Lee el preapproval completo
        pre_r = requests.get(f"{MP_PREAPPROVALS_URL}/{pre_id}", headers=mp_headers(), timeout=20)
        pre = pre_r.json()

        status = pre.get('status')  # authorized / paused / cancelled / ...
        external_reference = pre.get('external_reference', '')

        try:
            uid, page_id, kind = external_reference.split('|', 2)
        except Exception:
            uid, page_id, kind = None, None, None

        mongo.db.subscriptions.update_one(
            {"preapproval_id": pre_id},
            {"$set": {
                "preapproval_id": pre_id,
                "status": status,
                "last_event": datetime.utcnow(),
                "raw": pre,
                "page_id": ObjectId(page_id) if page_id else None,
                "user_id": ObjectId(uid) if uid else None,
                "provider": "mercado_pago"
            }},
            upsert=True
        )

        # ✅ Si se activó, marcamos el sitio como paid
        if page_id and status in ["authorized", "active", "charged"]:
            try:
                mongo.db.page_data.update_one(
                    {"_id": ObjectId(page_id)},
                    {"$set": {"plan": "paid"}}
                )
            except Exception as e:
                print("No se pudo marcar plan paid:", e)

        return "ok", 200

    except Exception as e:
        print("Sub webhook error:", e)
        return "error", 500

def get_page_by_slug(slug: str):
    return mongo.db.page_data.find_one({"slug": slug})

def ensure_page_has_slug(page):
    if page and not page.get('slug'):
        new_slug = unique_slug_for_page(page.get('business_name', 'sitio'))
        mongo.db.page_data.update_one({'_id': page['_id']}, {'$set': {'slug': new_slug}})
        page['slug'] = new_slug
    return page

@app.context_processor
def inject_pricing():
    pricing = compute_coupon_price()
    return dict(
        LIFETIME_PRICE=pricing["base_price"],
        SHOW_COUPON=pricing["show_coupon"],
        COUPON=pricing["coupon"],
        FINAL_PRICE=pricing["final_price"]
    )

def resolve_lifetime_price_for_checkout(coupon_param: str | None):
    """
    Devuelve (unit_price, applied_coupon_dict)
    - unit_price: float final para MP
    - applied_coupon_dict: info del cupón aplicado o None
    """
    pricing = compute_coupon_price()

    base_price = float(pricing["base_price"])
    show_coupon = pricing["show_coupon"]
    env_code = pricing["coupon"]["code"] if pricing["coupon"] else ""
    discount_amount = float(pricing["coupon"]["discount_amount"]) if pricing["coupon"] else 0.0

    # ¿El usuario pasó ?coupon=... y coincide con el de .env y está vigente?
    apply = bool(show_coupon and coupon_param and coupon_param.strip().upper() == env_code.upper())

    if apply and discount_amount > 0:
        final_price = round(max(base_price - discount_amount, 0), 2)
        applied = {
            "code": env_code,
            "type": pricing["coupon"]["type"],
            "value": pricing["coupon"]["value"],
            "discount_amount": discount_amount
        }
        return final_price, applied

    # Sin cupón válido → precio base
    return round(base_price, 2), None

def normalize_weekly_booking(data):
    """
    weekly: dict con keys "0".."6"
    cada día:
      - closed: bool
      - open: "HH:MM"
      - close: "HH:MM"
      - slot_minutes: int (opcional; si no, hereda global)
      - breaks: [{start:"HH:MM", end:"HH:MM"}]
    """
    weekly = data if isinstance(data, dict) else {}
    out = {}
    for k in ["0","1","2","3","4","5","6"]:
        d = weekly.get(k) or {}
        if not isinstance(d, dict):
            d = {}
        closed = bool(d.get("closed", False))
        open_h = (d.get("open") or "").strip()
        close_h = (d.get("close") or "").strip()
        breaks = d.get("breaks") if isinstance(d.get("breaks"), list) else []

        clean_breaks = []
        for b in breaks:
            if not isinstance(b, dict): 
                continue
            s = (b.get("start") or "").strip()
            e = (b.get("end") or "").strip()
            if s and e:
                clean_breaks.append({"start": s, "end": e})

        out[k] = {
            "closed": closed,
            "open": open_h if open_h else None,
            "close": close_h if close_h else None,
            "breaks": clean_breaks
        }
    return out


def get_booking_rules(page_id: ObjectId):
    """
    Fuente: page_data.booking_*
    - booking_enabled: bool
    - booking_slot_minutes: int (default global)
    - booking_weekly: dict (0..6) con open/close/closed/breaks
    """
    page = mongo.db.page_data.find_one(
        {"_id": ObjectId(page_id)},
        {
            "booking_enabled": 1,
            "booking_slot_minutes": 1,
            "booking_weekly": 1,
            "timezone": 1
        }
    ) or {}

    enabled = bool(page.get("booking_enabled", True))
    slot = int(page.get("booking_slot_minutes", 30) or 30)

    weekly = normalize_weekly_booking(page.get("booking_weekly") or {})
    # fallback simple si todavía no tienen weekly configurado:
    # Lun-Sáb 10-19, Dom cerrado
    if not any((weekly.get(str(i)) or {}).get("open") for i in range(7)):
        weekly = {
            "0": {"closed": False, "open": "10:00", "close": "19:00", "breaks": []},
            "1": {"closed": False, "open": "10:00", "close": "19:00", "breaks": []},
            "2": {"closed": False, "open": "10:00", "close": "19:00", "breaks": []},
            "3": {"closed": False, "open": "10:00", "close": "19:00", "breaks": []},
            "4": {"closed": False, "open": "10:00", "close": "19:00", "breaks": []},
            "5": {"closed": False, "open": "10:00", "close": "19:00", "breaks": []},
            "6": {"closed": True,  "open": None,   "close": None,   "breaks": []},
        }

    return {
        "enabled": enabled,
        "slot": slot,
        "weekly": weekly,
        "tz": (page.get("timezone") or "America/Mexico_City")
    }


def parse_date_ymd(dstr: str):
    y, m, d = [int(x) for x in dstr.split("-")]
    return date(y, m, d)


def dt_range_from_breaks(day: date, breaks: list[dict]):
    ranges = []
    for b in breaks or []:
        s = dt_at(day, b["start"])
        e = dt_at(day, b["end"])
        if s < e:
            ranges.append((s, e))
    return ranges


def is_in_breaks(dt_start: datetime, dt_end: datetime, break_ranges):
    for bs, be in break_ranges:
        if overlaps(dt_start, dt_end, bs, be):
            return True
    return False


def get_exception_for_day(page_id: ObjectId, day: date):
    """
    booking_exceptions:
      {page_id, date:"YYYY-MM-DD", type:"closed"|"custom_hours", open, close, breaks, reason}
    """
    dkey = day.strftime("%Y-%m-%d")
    ex = mongo.db.booking_exceptions.find_one(
        {"page_id": ObjectId(page_id), "date": dkey},
        {"type": 1, "open": 1, "close": 1, "breaks": 1, "reason": 1}
    )
    return ex

@app.route("/admin/booking/settings", methods=["GET", "POST"])
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required("admin")
def admin_booking_settings():
    page_id = get_current_page_id()
    rules = get_booking_rules(page_id)

    if request.method == "POST":
        enabled = request.form.get("booking_enabled") == "on"
        slot = int(request.form.get("booking_slot_minutes") or 30)

        # Espera inputs tipo:
        # open_0 close_0 closed_0, open_1 close_1 closed_1 ... open_6 close_6 closed_6
        weekly = {}
        for i in range(7):
            k = str(i)
            closed = request.form.get(f"closed_{k}") == "on"
            open_h = (request.form.get(f"open_{k}") or "").strip()
            close_h = (request.form.get(f"close_{k}") or "").strip()

            # breaks simple (1 break): break_start_0 / break_end_0 ...
            bstart = (request.form.get(f"break_start_{k}") or "").strip()
            bend   = (request.form.get(f"break_end_{k}") or "").strip()
            breaks = []
            if bstart and bend:
                breaks.append({"start": bstart, "end": bend})

            weekly[k] = {
                "closed": closed,
                "open": open_h if (open_h and not closed) else None,
                "close": close_h if (close_h and not closed) else None,
                "breaks": breaks
            }

        mongo.db.page_data.update_one(
            {"_id": ObjectId(page_id)},
            {"$set": {
                "booking_enabled": enabled,
                "booking_slot_minutes": slot,
                "booking_weekly": normalize_weekly_booking(weekly)
            }}
        )

        flash("Configuración de reservas actualizada ✅", "success")
        return redirect(url_for("admin_booking_settings"))

    return render_template("admin_booking_settings.html", rules=rules)

@app.route("/admin/booking/exceptions", methods=["GET", "POST"])
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required("admin")
def admin_booking_exceptions():
    page_id = get_current_page_id()

    if request.method == "POST":
        dstr = (request.form.get("date") or "").strip()  # YYYY-MM-DD
        typ  = (request.form.get("type") or "closed").strip()  # closed|custom_hours
        reason = (request.form.get("reason") or "").strip()

        if not dstr:
            flash("Fecha requerida.", "warning")
            return redirect(url_for("admin_booking_exceptions"))

        try:
            _ = parse_date_ymd(dstr)
        except Exception:
            flash("Fecha inválida (usa YYYY-MM-DD).", "danger")
            return redirect(url_for("admin_booking_exceptions"))

        now = datetime.utcnow()

        doc = {
            "page_id": ObjectId(page_id),
            "date": dstr,
            "type": typ,
            "reason": reason,
            "updated_at": now
        }

        if typ == "custom_hours":
            open_h = (request.form.get("open") or "").strip()
            close_h = (request.form.get("close") or "").strip()
            bstart = (request.form.get("break_start") or "").strip()
            bend   = (request.form.get("break_end") or "").strip()

            if not open_h or not close_h:
                flash("Open y Close requeridos para horario especial.", "warning")
                return redirect(url_for("admin_booking_exceptions"))

            doc["open"] = open_h
            doc["close"] = close_h
            doc["breaks"] = [{"start": bstart, "end": bend}] if (bstart and bend) else []
        else:
            doc["open"] = None
            doc["close"] = None
            doc["breaks"] = []

        mongo.db.booking_exceptions.update_one(
            {"page_id": ObjectId(page_id), "date": dstr},
            {
                "$set": doc,
                "$setOnInsert": {"created_at": now}
            },
            upsert=True
        )

        flash("Excepción guardada ✅", "success")
        return redirect(url_for("admin_booking_exceptions"))

    exceptions = list(
        mongo.db.booking_exceptions.find(
            {"page_id": ObjectId(page_id)}
        ).sort("date", 1)
    )

    return render_template("admin_booking_exceptions.html", exceptions=exceptions)

@app.route("/admin/booking/exceptions/<ex_id>", methods=["GET", "POST"])
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required("admin")
def admin_booking_exception_edit(ex_id):
    page_id = get_current_page_id()
    ex = mongo.db.booking_exceptions.find_one({"_id": ObjectId(ex_id), "page_id": ObjectId(page_id)})
    if not ex:
        flash("Excepción no encontrada.", "warning")
        return redirect(url_for("admin_booking_exceptions"))

    if request.method == "POST":
        dstr = (request.form.get("date") or "").strip()
        typ  = (request.form.get("type") or "closed").strip()
        reason = (request.form.get("reason") or "").strip()

        if not dstr:
            flash("Fecha requerida.", "warning")
            return redirect(url_for("admin_booking_exception_edit", ex_id=ex_id))

        try:
            _ = parse_date_ymd(dstr)
        except Exception:
            flash("Fecha inválida (YYYY-MM-DD).", "danger")
            return redirect(url_for("admin_booking_exception_edit", ex_id=ex_id))

        update = {
            "date": dstr,
            "type": typ,
            "reason": reason,
            "updated_at": datetime.utcnow()
        }

        if typ == "custom_hours":
            open_h = (request.form.get("open") or "").strip()
            close_h = (request.form.get("close") or "").strip()
            bstart = (request.form.get("break_start") or "").strip()
            bend   = (request.form.get("break_end") or "").strip()

            if not open_h or not close_h:
                flash("Open y Close requeridos.", "warning")
                return redirect(url_for("admin_booking_exception_edit", ex_id=ex_id))

            update["open"] = open_h
            update["close"] = close_h
            update["breaks"] = [{"start": bstart, "end": bend}] if (bstart and bend) else []
        else:
            update["open"] = None
            update["close"] = None
            update["breaks"] = []

        # Si cambió la fecha, puede chocar con unique index (page_id,date)
        # Solución: borrar el doc actual y upsert al nuevo key
        if dstr != ex.get("date"):
            mongo.db.booking_exceptions.delete_one({"_id": ex["_id"], "page_id": ObjectId(page_id)})
            mongo.db.booking_exceptions.update_one(
                {"page_id": ObjectId(page_id), "date": dstr},
                {"$set": {**update, "page_id": ObjectId(page_id)}, "$setOnInsert": {"created_at": ex.get("created_at") or datetime.utcnow()}},
                upsert=True
            )
        else:
            mongo.db.booking_exceptions.update_one(
                {"_id": ex["_id"], "page_id": ObjectId(page_id)},
                {"$set": update}
            )

        flash("Excepción actualizada ✅", "success")
        return redirect(url_for("admin_booking_exceptions"))

    return render_template("admin_booking_exception_edit.html", ex=ex)

@app.route("/admin/booking/exceptions/<ex_id>/delete", methods=["POST"])
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required("admin")
def admin_booking_exception_delete(ex_id):
    page_id = get_current_page_id()
    mongo.db.booking_exceptions.delete_one({"_id": ObjectId(ex_id), "page_id": ObjectId(page_id)})
    flash("Excepción eliminada ✅", "success")
    return redirect(url_for("admin_booking_exceptions"))

@app.route("/admin/appointments/new", methods=["GET", "POST"])
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required("admin")
def admin_appointments_new():
    page_id = get_current_page_id()

    if request.method == "POST":
        customer_name = (request.form.get("customer_name") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        service_title = (request.form.get("service_title") or "").strip()
        start_iso = (request.form.get("start_at") or "").strip()  # "YYYY-MM-DDTHH:MM"
        status = (request.form.get("status") or "approved").strip()  # pending|approved

        if not customer_name or not phone or not service_title or not start_iso:
            flash("Completa todos los campos.", "warning")
            return redirect(url_for("admin_appointments_new"))

        try:
            # viene sin zona, pero en tu app ya usas naive UTC en muchos lados
            start_at = datetime.fromisoformat(start_iso)
        except Exception:
            flash("Fecha/hora inválida.", "danger")
            return redirect(url_for("admin_appointments_new"))

        rules = get_booking_rules(page_id)
        if not rules["enabled"]:
            flash("Reservas deshabilitadas.", "warning")
            return redirect(url_for("admin_appointments_new"))

        slot_minutes = int(rules["slot"])
        end_at = start_at + timedelta(minutes=slot_minutes)

        # choque
        conflict = mongo.db.appointments.find_one({
            "page_id": ObjectId(page_id),
            "status": {"$in": ["pending", "approved"]},
            "start_at": {"$lt": end_at},
            "end_at": {"$gt": start_at}
        })
        if conflict:
            flash("Ese horario ya está ocupado.", "danger")
            return redirect(url_for("admin_appointments_new"))

        appt = {
            "page_id": ObjectId(page_id),
            "slug": (g.page_slug or ""),
            "customer_name": customer_name,
            "phone": phone,
            "service_title": service_title,
            "start_at": start_at,
            "end_at": end_at,
            "duration_min": slot_minutes,
            "status": status,
            "source": "dashboard",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        mongo.db.appointments.insert_one(appt)

        flash("Cita creada ✅", "success")
        return redirect(url_for("admin_appointments"))

    return render_template("admin_appointments_new.html")

@app.route("/admin/appointments/<appt_id>/edit", methods=["GET", "POST"])
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required("admin")
def admin_appointments_edit(appt_id):
    page_id = get_current_page_id()
    appt = mongo.db.appointments.find_one({"_id": ObjectId(appt_id), "page_id": ObjectId(page_id)})
    if not appt:
        flash("Cita no encontrada.", "warning")
        return redirect(url_for("admin_appointments"))

    if request.method == "POST":
        customer_name = (request.form.get("customer_name") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        service_title = (request.form.get("service_title") or "").strip()
        start_iso = (request.form.get("start_at") or "").strip()
        status = (request.form.get("status") or appt.get("status") or "pending").strip()

        if not customer_name or not phone or not service_title or not start_iso:
            flash("Completa todos los campos.", "warning")
            return redirect(url_for("admin_appointments_edit", appt_id=appt_id))

        try:
            start_at = datetime.fromisoformat(start_iso)
        except Exception:
            flash("Fecha/hora inválida.", "danger")
            return redirect(url_for("admin_appointments_edit", appt_id=appt_id))

        rules = get_booking_rules(page_id)
        slot_minutes = int(appt.get("duration_min") or rules["slot"] or 30)
        end_at = start_at + timedelta(minutes=slot_minutes)

        # choque (excluye esta misma cita)
        conflict = mongo.db.appointments.find_one({
            "_id": {"$ne": ObjectId(appt_id)},
            "page_id": ObjectId(page_id),
            "status": {"$in": ["pending", "approved"]},
            "start_at": {"$lt": end_at},
            "end_at": {"$gt": start_at}
        })
        if conflict:
            flash("Ese horario ya está ocupado.", "danger")
            return redirect(url_for("admin_appointments_edit", appt_id=appt_id))

        mongo.db.appointments.update_one(
            {"_id": ObjectId(appt_id), "page_id": ObjectId(page_id)},
            {"$set": {
                "customer_name": customer_name,
                "phone": phone,
                "service_title": service_title,
                "start_at": start_at,
                "end_at": end_at,
                "status": status,
                "updated_at": datetime.utcnow()
            }}
        )

        flash("Cita actualizada ✅", "success")
        return redirect(url_for("admin_appointments"))

    # Para el input datetime-local: "YYYY-MM-DDTHH:MM"
    start_local = ""
    try:
        start_local = appt["start_at"].strftime("%Y-%m-%dT%H:%M")
    except Exception:
        pass

    return render_template("admin_appointments_edit.html", appt=appt, start_local=start_local)

@app.route("/admin/appointments/<appt_id>/cancel", methods=["POST"])
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required("admin")
def admin_appointments_cancel(appt_id):
    page_id = get_current_page_id()
    mongo.db.appointments.update_one(
        {"_id": ObjectId(appt_id), "page_id": ObjectId(page_id)},
        {"$set": {"status": "cancelled", "updated_at": datetime.utcnow()}}
    )
    flash("Cita cancelada ✅", "success")
    return redirect(url_for("admin_appointments"))


@app.route("/admin/appointments/<appt_id>/delete", methods=["POST"])
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required("admin")
def admin_appointments_delete(appt_id):
    page_id = get_current_page_id()
    mongo.db.appointments.delete_one({"_id": ObjectId(appt_id), "page_id": ObjectId(page_id)})
    flash("Cita eliminada ✅", "success")
    return redirect(url_for("admin_appointments"))

@app.route('/', methods=['GET'])
def index():
    page = int(request.args.get('page', 1))
    per_page = 6  # negocios por página

    search_query = request.args.get('q', '').strip()
    selected_category = request.args.get('category', '').strip()
    selected_state = request.args.get('state', '').strip()

    filtro = {}
    if search_query:
        filtro['business_name'] = {"$regex": search_query, "$options": "i"}
    if selected_category:
        filtro['category'] = selected_category
    if selected_state:
        filtro['state'] = selected_state

    total = mongo.db.page_data.count_documents(filtro)
    negocios = mongo.db.page_data.find(filtro).skip((page - 1) * per_page).limit(per_page)

    return render_template('index.html', negocios=negocios, page=page, per_page=per_page, total=total)


@app.route('/register', methods=['GET', 'POST'])
def register():
    page_id = request.args.get('page_id') if request.method == 'GET' else request.form.get('page_id')
    if not page_id:
        flash('No se puede registrar un usuario sin una empresa asociada.', 'warning')
        return redirect(url_for('create_page'))

    # Validar que la empresa exista
    try:
        page_oid = ObjectId(page_id)
    except Exception:
        flash('ID de empresa inválido.', 'danger')
        return redirect(url_for('create_page'))

    page = mongo.db.page_data.find_one({'_id': page_oid})
    if not page:
        flash('Empresa no encontrada.', 'danger')
        return redirect(url_for('create_page'))

    if request.method == 'POST':
        if request.form.get('accept_tos') != 'on':
            flash('Debes aceptar los Términos y Condiciones para registrarte.', 'warning')
            return redirect(url_for('register', page_id=page_id))

        nombre = (request.form.get('nombre') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        raw_password = request.form.get('password') or ''

        if not nombre or not email or not raw_password:
            flash('Completa todos los campos.', 'warning')
            return redirect(url_for('register', page_id=page_id))

        # ¿Existe ya el correo?
        if mongo.db.users.find_one({'email': email}):
            flash('Este correo ya existe.', 'danger')
            return redirect(url_for('register', page_id=page_id))

        # Primer usuario de la empresa = admin, siguientes = editor
        existing_count = mongo.db.users.count_documents({'page_id': page_oid})
        assigned_role = 'admin' if existing_count == 0 else 'editor'

        user_doc = {
            'nombre': nombre,
            'email': email,
            'password': generate_password_hash(raw_password),
            'confirmed': False,
            'role': assigned_role,
            'page_id': page_oid,          # legacy
            'page_ids': [page_oid],       # nuevo
            'current_page_id': page_oid   # dejarlo activo
        }
        ins = mongo.db.users.insert_one(user_doc)
        user_doc['_id'] = ins.inserted_id

        # Enviar confirmación (no bloquea onboarding)
        try:
            token = s.dumps(email, salt='email-confirm')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            html = render_template('confirm_email.html', confirm_url=confirm_url)
            msg = Message('Confirma tu correo', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.html = html
            mail.send(msg)
            flash('Revisa tu correo para confirmar tu cuenta.', 'info')
        except Exception:
            flash('No se pudo enviar el correo de confirmación ahora mismo. Puedes reintentar después.', 'warning')

        # ✅ Importante: primero login, luego set_current_page_id
        login_user(User(user_doc))
        set_current_page_id(page_oid)
        ensure_user_page_lists(current_user.id, page_oid)

        flash('Cuenta creada ✅ Bienvenido!', 'success')
        return redirect(url_for('billing_portal'))

    return render_template('register.html', page_id=str(page_id))

@app.route('/admin/register_user', methods=['GET', 'POST'])
@login_required
def admin_register_user():
    # Solo admins pueden crear usuarios
    if current_user.role != 'admin':
        flash('No tienes permiso para acceder a esta página.')
        return redirect(url_for('index'))

    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona o crea un sitio.')
        return redirect(url_for('sites'))

    if request.method == 'POST':
        nombre = request.form['nombre'].strip()
        email = request.form['email'].strip().lower()
        raw_password = request.form['password']
        requested_role = request.form['role'].strip()  # 'admin' o 'editor'

        if mongo.db.users.find_one({'email': email}):
            flash('Este correo ya existe')
            return redirect(url_for('admin_register_user'))

        # Si ya hay un admin en esta empresa, forzar 'editor'
        already_admin = mongo.db.users.find_one({'page_id': page_id, 'role': 'admin'})
        final_role = requested_role if not already_admin else 'editor'

        user_doc = {
            'nombre': nombre,
            'email': email,
            'password': generate_password_hash(raw_password),
            'confirmed': False,
            'role': final_role,
            'page_id': page_id,
            'page_ids': [page_id],
            'current_page_id': page_id
        }
        mongo.db.users.insert_one(user_doc)

        try:
            token = s.dumps(email, salt='email-confirm')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            html = render_template('confirm_email.html', confirm_url=confirm_url)
            msg = Message('Confirma tu correo', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.html = html
            mail.send(msg)
        except Exception:
            pass

        flash('Usuario registrado. Revisa el correo para confirmar la cuenta.')
        return redirect(url_for('manage_users'))

    return render_template('admin_register_user.html', page_id=str(page_id))

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        mongo.db.users.update_one({'email': email}, {'$set': {'confirmed': True}})
        flash('Cuenta confirmada. Ahora puedes iniciar sesión.')
    except Exception as e:
        flash('El enlace de confirmación es inválido o ha expirado.')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''

        if not email or not password:
            flash('Completa correo y contraseña.', 'warning')
            return redirect(url_for('login'))

        user_data = mongo.db.users.find_one({'email': email})
        if not user_data:
            flash('Credenciales inválidas.', 'danger')
            return redirect(url_for('login'))

        stored_hash = (
            user_data.get('password')
            or user_data.get('password_hash')
            or user_data.get('hashed_password')
        )

        if not stored_hash:
            flash('Tu cuenta no tiene contraseña configurada. Usa "Restablecer contraseña".', 'warning')
            return redirect(url_for('reset_password'))

        ok = False

        # werkzeug (pbkdf2:, scrypt:)
        try:
            if isinstance(stored_hash, str) and (stored_hash.startswith('pbkdf2:') or stored_hash.startswith('scrypt:')):
                ok = check_password_hash(stored_hash, password)
        except Exception:
            ok = False

        # bcrypt ($2b$...)
        if not ok:
            try:
                if isinstance(stored_hash, str) and stored_hash.startswith('$2'):
                    ok = bcrypt.check_password_hash(stored_hash, password)
            except Exception:
                ok = False

        # fallback
        if not ok:
            try:
                ok = check_password_hash(stored_hash, password)
            except Exception:
                ok = False

        if ok:
            login_user(User(user_data))
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('dashboard'))

        flash('Credenciales inválidas.', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/crear_post_negocio', methods=['GET', 'POST'])
@require_active_subscription
@login_required
def crear_post_negocio():
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    if user is None:
        flash('No se encontró el usuario.')
        return redirect(url_for('dashboard'))

    page_id = user.get('page_id')

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        files = request.files.getlist('files')
        cabecera_file = request.files.get('cabecera')

        negocio = mongo.db.page_data.find_one({'_id': ObjectId(page_id)})
        slug_page = slugify(negocio['business_name']) if negocio else 'unknown'
        today = datetime.utcnow().strftime('%Y-%m-%d')

        # Ruta fuera de static
        post_folder = os.path.join(app.config['UPLOAD_FOLDER'], slug_page, today)
        os.makedirs(post_folder, exist_ok=True)

        saved_files = []
        for file in files:
            if file and allowed_file(file.filename):
                original_name = secure_filename(file.filename)
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{original_name}"
                file_path = os.path.join(post_folder, filename)
                file.save(file_path)
                saved_files.append(f"{slug_page}/{today}/{filename}")  # Ruta relativa para base de datos

        # Cabecera
        cabecera_filename = None
        if cabecera_file and allowed_file(cabecera_file.filename):
            original_name = secure_filename(cabecera_file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            cabecera_filename = f"{timestamp}_{original_name}"
            cabecera_path = os.path.join(post_folder, cabecera_filename)
            cabecera_file.save(cabecera_path)
            cabecera_filename = f"{slug_page}/{today}/{cabecera_filename}"

        post = {
            'title': title,
            'content': content,
            'files': saved_files,
            'cabecera': cabecera_filename,
            'date': datetime.utcnow(),
            'page_id': page_id,
            'author': current_user.nombre
        }

        mongo.db.posts.insert_one(post)
        flash('Publicación creada exitosamente para el negocio.')
        return redirect(url_for('list_post'))

    return render_template('crear_post_negocio.html')


@app.route('/list_post')
@require_active_subscription
@current_site(required=True)
@login_required
def list_post():
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    except Exception as e:
        flash("Error al obtener usuario.", "danger")
        return redirect(url_for('login'))

    if not user:
        flash("Usuario no encontrado.", "warning")
        return redirect(url_for('login'))

    page_id = user.get('page_id')

    if not page_id:
        flash("No se encontró un sitio o página asociada al usuario.", "warning")
        return redirect(url_for('dashboard'))

    posts = list(
        mongo.db.posts.find({'page_id': page_id}).sort('date', -1)
    )

    return render_template('list_post.html', posts=posts, total_posts=len(posts))

@app.route('/edit_post/<post_id>', methods=['GET', 'POST'])
@require_active_subscription
@login_required
def edit_post(post_id):
    post = mongo.db.posts.find_one({'_id': ObjectId(post_id)})

    if not post:
        flash('Post no encontrado.')
        return redirect(url_for('dashboard'))

    user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})

    es_autor = post.get('author') == current_user.email
    es_admin = current_user.role == 'admin'
    misma_page = user.get('page_id') == post.get('page_id')

    if not (es_autor or es_admin or misma_page):
        flash('No autorizado.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        file = request.files.get('file')
        cabecera_file = request.files.get('cabecera')

        file_url = post.get('file_url')
        cabecera = post.get('cabecera')

        # Obtener carpeta de negocio
        negocio = mongo.db.page_data.find_one({'_id': ObjectId(post.get('page_id'))})
        slug_page = slugify(negocio['business_name']) if negocio else 'unknown'
        today = datetime.utcnow().strftime('%Y-%m-%d')
        upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], slug_page, today)
        os.makedirs(upload_folder, exist_ok=True)

        # Adjuntos (archivo extra)
        if file and allowed_file(file.filename):
            original_name = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{original_name}"
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)
            file_url = f"{slug_page}/{today}/{filename}"

        # Imagen de cabecera
        if cabecera_file and allowed_file(cabecera_file.filename):
            original_name = secure_filename(cabecera_file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            cabecera_filename = f"{timestamp}_{original_name}"
            cabecera_path = os.path.join(upload_folder, cabecera_filename)
            cabecera_file.save(cabecera_path)
            cabecera = f"{slug_page}/{today}/{cabecera_filename}"

        mongo.db.posts.update_one({'_id': ObjectId(post_id)}, {
            '$set': {
                'title': title,
                'content': content,
                'file_url': file_url,
                'cabecera': cabecera
            }
        })

        flash('Post actualizado correctamente.')
        return redirect(url_for('dashboard'))

    return render_template('edit_post.html', post=post)


@app.route('/delete_post/<post_id>')
@require_active_subscription
@login_required
def delete_post(post_id):
    post = mongo.db.posts.find_one({'_id': ObjectId(post_id)})

    if not post:
        flash('Post no encontrado.')
        return redirect(url_for('dashboard'))

    # Eliminar archivos asociados (archivos y cabecera)
    # Asumiendo que tus rutas de archivo son relativas, tipo: "davani-technology/2025-06-03/archivo.jpg"
    for file_field in ['file_url', 'cabecera']:
        file_rel_path = post.get(file_field)
        if file_rel_path:
            # Construir ruta absoluta en disco
            file_abs_path = os.path.join(app.config['UPLOAD_FOLDER'], file_rel_path)
            # Comprobar si existe y eliminar
            if os.path.exists(file_abs_path):
                try:
                    os.remove(file_abs_path)
                except Exception as e:
                    # Opcional: loggear error o avisar
                    print(f"Error eliminando archivo {file_abs_path}: {e}")

    # Borrar el post de la base de datos
    mongo.db.posts.delete_one({'_id': ObjectId(post_id)})
    flash('Post eliminado correctamente.')
    return redirect(url_for('dashboard'))


@app.route('/posts')
@require_active_subscription
@login_required
def posts():
    posts = list(mongo.db.posts.find().sort('date', -1))
    return render_template('posts.html', posts=posts)

# --- NUEVA: /dashboard/<slug> ---

@app.route('/dashboard/<slug>')
@login_required
@require_active_subscription
def dashboard_slug(slug):
    page = get_page_by_slug(slug)
    if not page:
        flash('Sitio no encontrado.')
        return redirect(url_for('sites'))

    set_current_page_id(page['_id'])
    page = ensure_page_has_slug(page)

    page_id = page['_id']

    # --- Stats (conteos) ---
    stats = {
        'posts':     mongo.db.posts.count_documents({'page_id': page_id}),
        'avisos':    mongo.db.avisos.count_documents({'page_id': page_id}),
        'productos': mongo.db.productos.count_documents({'page_id': page_id}),
        'resenas':   mongo.db.reseñas.count_documents({'page_id': page_id}) if 'reseñas' in mongo.db.list_collection_names() else 0,
        'usuarios':  mongo.db.users.count_documents({}) if current_user.role == 'admin' else 0,
    }

    # --- Recientes (top 6) ---
    recientes = {
        'posts':     list(mongo.db.posts.find({'page_id': page_id}).sort('created_at', -1).limit(6)),
        'avisos':    list(mongo.db.avisos.find({'page_id': page_id}).sort('created_at', -1).limit(6)),
        'productos': list(mongo.db.productos.find({'page_id': page_id}).sort('created_at', -1).limit(6)),
    }

    # =========================
    # Analytics 7 días
    # =========================
    since = datetime.utcnow() - timedelta(days=7)

    analytics_rows = list(mongo.db.events.aggregate([
        {"$match": {"page_id": page_id, "ts": {"$gte": since}}},
        {"$group": {"_id": "$type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]))
    analytics = {r["_id"]: r["count"] for r in analytics_rows}

    # Vistas últimos 7 días (serie simple por día)
    daily = list(mongo.db.events.aggregate([
        {"$match": {"page_id": page_id, "type": "view", "ts": {"$gte": since}}},
        {"$project": {"d": {"$dateToString": {"format": "%Y-%m-%d", "date": "$ts"}}}},
        {"$group": {"_id": "$d", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]))

    # =========================
    # Leads
    # =========================
    leads_total = mongo.db.leads.count_documents({"page_id": page_id}) if "leads" in mongo.db.list_collection_names() else 0
    leads_7d = mongo.db.leads.count_documents({"page_id": page_id, "created_at": {"$gte": since}}) if "leads" in mongo.db.list_collection_names() else 0
    leads_recent = list(mongo.db.leads.find({"page_id": page_id}).sort("created_at", -1).limit(10)) if "leads" in mongo.db.list_collection_names() else []

    # =========================
    # Citas / Reservas
    # =========================
    appt_pending = mongo.db.appointments.count_documents({"page_id": page_id, "status": "pending"}) if "appointments" in mongo.db.list_collection_names() else 0
    appt_total = mongo.db.appointments.count_documents({"page_id": page_id}) if "appointments" in mongo.db.list_collection_names() else 0
    appt_upcoming = list(mongo.db.appointments.find({"page_id": page_id}).sort("start_at", 1).limit(10)) if "appointments" in mongo.db.list_collection_names() else []

    # =========================
    # Promos activas
    # =========================
    now = datetime.utcnow()
    promos_active = mongo.db.promos.count_documents({
        "page_id": page_id,
        "active": True,
        "starts_at": {"$lte": now},
        "$or": [{"ends_at": None}, {"ends_at": {"$gte": now}}]
    }) if "promos" in mongo.db.list_collection_names() else 0

    # =========================
    # Ventas / POS
    # =========================
    start_today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    end_today = datetime.utcnow().replace(hour=23, minute=59, second=59, microsecond=999999)

    ventas_total = mongo.db.ventas.count_documents({"page_id": page_id}) if "ventas" in mongo.db.list_collection_names() else 0
    ventas_hoy_docs = list(mongo.db.ventas.find({
        "page_id": page_id,
        "status": "paid",
        "created_at": {"$gte": start_today, "$lte": end_today}
    })) if "ventas" in mongo.db.list_collection_names() else []

    ventas_hoy = len(ventas_hoy_docs)
    ingreso_hoy = money2(sum(money2(v.get("total", 0)) for v in ventas_hoy_docs))
    efectivo_hoy = money2(sum(money2(v.get("cash_amount", 0)) for v in ventas_hoy_docs))
    digital_hoy = money2(sum(money2(v.get("digital_amount", 0)) for v in ventas_hoy_docs))

    stock_bajo = mongo.db.productos.count_documents({
        "page_id": page_id,
        "track_inventory": True,
        "$expr": {"$lte": ["$stock", "$min_stock"]}
    }) if "productos" in mongo.db.list_collection_names() else 0

    ventas_recent = list(mongo.db.ventas.find({
        "page_id": page_id
    }).sort("created_at", -1).limit(10)) if "ventas" in mongo.db.list_collection_names() else []

    return render_template(
        'dashboard.html',
        page=page,
        stats=stats,
        recientes=recientes,
        ventas_total=ventas_total,
        ventas_hoy=ventas_hoy,
        ingreso_hoy=ingreso_hoy,
        efectivo_hoy=efectivo_hoy,
        digital_hoy=digital_hoy,
        stock_bajo=stock_bajo,
        ventas_recent=ventas_recent,
        analytics=analytics,
        daily_views=daily,
        leads_total=leads_total,
        leads_7d=leads_7d,
        leads_recent=leads_recent,
        appt_total=appt_total,
        appt_pending=appt_pending,
        appt_upcoming=appt_upcoming,
        promos_active=promos_active
    )

# Compat: /dashboard → /dashboard/<slug>
@app.route('/dashboard')
@require_active_subscription
@login_required
def dashboard():
    page_id = get_current_page_id()
    page = mongo.db.page_data.find_one({'_id': page_id}) if page_id else None
    if not page:
        flash('Selecciona o crea un sitio.')
        return redirect(url_for('sites'))
    page = ensure_page_has_slug(page)
    return redirect(url_for('dashboard_slug', slug=page['slug']))

# AVISOS
@app.route('/avisos')
@require_active_subscription
@login_required
def list_avisos():
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.')
        return redirect(url_for('sites'))
    avisos = list(mongo.db.avisos.find({'page_id': page_id}).sort('date', -1))
    return render_template('list_avisos.html', avisos=avisos)

# Ruta para crear un nuevo aviso
@app.route('/create_aviso', methods=['GET', 'POST'])
@require_active_subscription
@login_required
def create_aviso():
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    page_id = user.get('page_id')  # o el nombre que hayas usado
    if not user:
        flash('Error al encontrar el usuario actual.')
        return redirect(url_for('logout'))  # o a donde prefieras

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        date = datetime.now()

        # Insertar el aviso en la base de datos
        mongo.db.avisos.insert_one({
            'title': title,
            'content': content,
            'date': date,
            'author': current_user.id,
            'page_id': page_id
        })
        flash('Aviso creado correctamente.')
        return redirect(url_for('list_avisos'))

    return render_template('create_aviso.html')

# Ruta para editar un aviso
@app.route('/edit_aviso/<aviso_id>', methods=['GET', 'POST'])
@require_active_subscription
@login_required
def edit_aviso(aviso_id):
    aviso = mongo.db.avisos.find_one({'_id': ObjectId(aviso_id)})

    if not aviso or aviso['author'] != current_user.id:
        flash('No autorizado.')
        return redirect(url_for('list_avisos'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        mongo.db.avisos.update_one({'_id': ObjectId(aviso_id)}, {
            '$set': {
                'title': title,
                'content': content,
                'date': datetime.now()
            }
        })
        flash('Aviso actualizado correctamente.')
        return redirect(url_for('list_avisos'))

    return render_template('edit_aviso.html', aviso=aviso)

# Ruta para eliminar un aviso
@app.route('/delete_aviso/<aviso_id>')
@require_active_subscription
@login_required
def delete_aviso(aviso_id):
    aviso = mongo.db.avisos.find_one({'_id': ObjectId(aviso_id)})
    if aviso and aviso['author'] == current_user.id:
        mongo.db.avisos.delete_one({'_id': ObjectId(aviso_id)})
        flash('Aviso eliminado correctamente.')
    return redirect(url_for('list_avisos'))

def parse_float(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return default

def parse_int(v, default=0):
    try:
        return int(v)
    except Exception:
        return default

def money2(v):
    return round(float(v or 0), 2)

def next_sale_folio(page_id):
    row = mongo.db.counters.find_one_and_update(
        {'_id': f'sales:{str(page_id)}'},
        {'$inc': {'seq': 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    seq = int(row.get('seq', 1))
    return f"V-{seq:06d}"

def get_producto_by_id_for_page(producto_id, page_id):
    return mongo.db.productos.find_one({
        '_id': ObjectId(str(producto_id)),
        'page_id': ObjectId(str(page_id))
    })

def registrar_venta(page_id, items, payment_method,
                    cash_amount=0, digital_amount=0,
                    customer_name='', customer_phone='',
                    notes='', tipo='mostrador'):
    """
    items esperado:
    [
      {"producto_id": "...", "qty": 2},
      ...
    ]
    """
    page_id = ObjectId(str(page_id))
    if not items:
        raise ValueError("No hay productos en la venta.")

    sale_items = []
    subtotal = 0.0
    stock_rollback = []

    for raw in items:
        producto_id = raw.get('producto_id')
        qty = parse_int(raw.get('qty'), 0)

        if not producto_id or qty <= 0:
            continue

        producto = mongo.db.productos.find_one({
            '_id': ObjectId(str(producto_id)),
            'page_id': page_id,
            'active': {'$ne': False}
        })

        if not producto:
            raise ValueError("Uno de los productos no existe o no pertenece al sitio actual.")

        title = producto.get('title', 'Producto')
        price = money2(producto.get('price', 0))
        sku = (producto.get('sku') or '').strip()
        barcode = (producto.get('barcode') or '').strip()
        track_inventory = bool(producto.get('track_inventory', False))

        if track_inventory:
            updated = mongo.db.productos.find_one_and_update(
                {
                    '_id': producto['_id'],
                    'page_id': page_id,
                    'stock': {'$gte': qty}
                },
                {
                    '$inc': {'stock': -qty},
                    '$set': {'updated_at': datetime.utcnow()}
                },
                return_document=ReturnDocument.AFTER
            )

            if not updated:
                for rb in stock_rollback:
                    mongo.db.productos.update_one(
                        {'_id': rb['producto_id'], 'page_id': page_id},
                        {'$inc': {'stock': rb['qty']}}
                    )
                raise ValueError(f"Stock insuficiente para {title}")

            stock_rollback.append({
                'producto_id': producto['_id'],
                'qty': qty
            })

        line_subtotal = money2(price * qty)
        subtotal += line_subtotal

        sale_items.append({
            'producto_id': producto['_id'],
            'title': title,
            'sku': sku,
            'barcode': barcode,
            'qty': qty,
            'unit_price': price,
            'subtotal': line_subtotal,
            'track_inventory': track_inventory
        })

    if not sale_items:
        raise ValueError("No hay productos válidos en la venta.")

    subtotal = money2(subtotal)
    discount = 0.0
    total = money2(subtotal - discount)

    cash_amount = money2(cash_amount)
    digital_amount = money2(digital_amount)

    if payment_method == 'efectivo':
        cash_amount = total
        digital_amount = 0.0
    elif payment_method in ['transferencia', 'tarjeta', 'digital']:
        cash_amount = 0.0
        digital_amount = total
    elif payment_method == 'mixto':
        if money2(cash_amount + digital_amount) != total:
            for rb in stock_rollback:
                mongo.db.productos.update_one(
                    {'_id': rb['producto_id'], 'page_id': page_id},
                    {'$inc': {'stock': rb['qty']}}
                )
            raise ValueError("En pago mixto, efectivo + digital debe ser igual al total.")

    venta = {
        'page_id': page_id,
        'folio': next_sale_folio(page_id),
        'tipo': tipo,  # mostrador | catalogo
        'status': 'paid',
        'customer_name': customer_name.strip(),
        'customer_phone': customer_phone.strip(),
        'items': sale_items,
        'subtotal': subtotal,
        'discount': discount,
        'total': total,
        'payment_method': payment_method,
        'cash_amount': cash_amount,
        'digital_amount': digital_amount,
        'notes': notes.strip(),
        'created_by': ObjectId(current_user.id),
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow(),
    }

    ins = mongo.db.ventas.insert_one(venta)
    venta['_id'] = ins.inserted_id
    return venta

def normalize_product_code(value: str) -> str:
    v = (value or '').strip().upper()
    v = re.sub(r'[^A-Z0-9\-_\.]', '', v)
    return v

def generate_product_code(page_id, title=''):
    base = slugify(title or 'producto').upper().replace('-', '')
    base = base[:8] if base else 'PRODUCTO'

    while True:
        rand = os.urandom(3).hex().upper()
        code = f"{base}-{rand}"
        exists = mongo.db.productos.find_one({
            'page_id': ObjectId(str(page_id)),
            'barcode': code
        })
        if not exists:
            return code

def barcode_exists(page_id, barcode, exclude_id=None):
    if not barcode:
        return False

    q = {
        'page_id': ObjectId(str(page_id)),
        'barcode': barcode
    }

    if exclude_id:
        q['_id'] = {'$ne': ObjectId(str(exclude_id))}

    return mongo.db.productos.find_one(q) is not None

# productos
@app.route('/productos')
@require_active_subscription
@login_required
def list_productos():
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.')
        return redirect(url_for('sites'))

    productos = list(
        mongo.db.productos.find({'page_id': page_id}).sort('title', 1)
    )

    low_stock_count = sum(
        1 for p in productos
        if p.get('track_inventory') and int(p.get('stock', 0)) <= int(p.get('min_stock', 0))
    )

    return render_template(
        'list_productos.html',
        productos=productos,
        low_stock_count=low_stock_count
    )

from werkzeug.utils import secure_filename
import os

@app.route('/create_producto', methods=['GET', 'POST'])
@require_active_subscription
@login_required
def create_producto():
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.')
        return redirect(url_for('sites'))

    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        description = (request.form.get('description') or '').strip()
        price = parse_float(request.form.get('price'), 0)
        show_price = 'show_price' in request.form
        tipo = (request.form.get('tipo') or 'producto').strip().lower()

        sku = normalize_product_code(request.form.get('sku'))
        barcode = normalize_product_code(request.form.get('barcode'))
        stock = parse_int(request.form.get('stock'), 0)
        min_stock = parse_int(request.form.get('min_stock'), 0)
        track_inventory = request.form.get('track_inventory') == 'on'
        active = request.form.get('active', 'on') == 'on'

        if not title:
            flash('El título es obligatorio.', 'warning')
            return redirect(url_for('create_producto'))

        # Si no mandaron barcode, se genera automáticamente
        if not barcode:
            barcode = generate_product_code(page_id, title)

        # Evitar duplicados por sitio
        if barcode_exists(page_id, barcode):
            flash('Ese código de barras / QR ya existe en este sitio.', 'danger')
            return redirect(url_for('create_producto'))

        image_file = request.files.get('image')
        image_path = None

        if image_file and image_file.filename != '':
            slug = slugify(title)
            today = datetime.utcnow().strftime('%Y-%m-%d')
            folder = os.path.join(app.config['UPLOAD_FOLDER'], slug, today)
            os.makedirs(folder, exist_ok=True)

            filename = secure_filename(image_file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            final_filename = f"{timestamp}_{filename}"
            full_path = os.path.join(folder, final_filename)
            image_file.save(full_path)

            image_path = f"{slug}/{today}/{final_filename}"

        mongo.db.productos.insert_one({
            'title': title,
            'description': description,
            'price': money2(price),
            'image': image_path,
            'page_id': page_id,
            'show_price': show_price,
            'tipo': tipo,
            'sku': sku,
            'barcode': barcode,
            'qr_value': barcode,   # QR reutiliza el mismo valor para POS
            'stock': stock,
            'min_stock': min_stock,
            'track_inventory': track_inventory,
            'active': active,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
        })

        flash('Elemento creado correctamente.', 'success')
        return redirect(url_for('list_productos'))

    tipos_posibles = ['producto', 'servicio']
    return render_template('create_producto.html', tipos_posibles=tipos_posibles)

@app.route('/edit_producto/<producto_id>', methods=['GET', 'POST'])
@require_active_subscription
@login_required
def edit_producto(producto_id):
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.')
        return redirect(url_for('sites'))

    producto = mongo.db.productos.find_one({
        '_id': ObjectId(producto_id),
        'page_id': page_id
    })

    if not producto:
        flash('Producto no encontrado.')
        return redirect(url_for('list_productos'))

    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        description = (request.form.get('description') or '').strip()
        price = parse_float(request.form.get('price'), 0)
        show_price = 'show_price' in request.form
        tipo = (request.form.get('tipo') or 'producto').strip().lower()

        sku = normalize_product_code(request.form.get('sku'))
        barcode = normalize_product_code(request.form.get('barcode'))
        stock = parse_int(request.form.get('stock'), 0)
        min_stock = parse_int(request.form.get('min_stock'), 0)
        track_inventory = request.form.get('track_inventory') == 'on'
        active = request.form.get('active', 'on') == 'on'

        image_file = request.files.get('image')
        image_path = producto.get('image')

        if image_file and image_file.filename != '':
            slug = slugify(title or producto.get('title', 'producto'))
            today = datetime.utcnow().strftime('%Y-%m-%d')
            folder = os.path.join(app.config['UPLOAD_FOLDER'], slug, today)
            os.makedirs(folder, exist_ok=True)

            filename = secure_filename(image_file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            final_filename = f"{timestamp}_{filename}"
            full_path = os.path.join(folder, final_filename)
            image_file.save(full_path)

            image_path = f"{slug}/{today}/{final_filename}"

        if not barcode:
            barcode = generate_product_code(page_id, title or producto.get('title'))

        if barcode_exists(page_id, barcode, exclude_id=producto_id):
            flash('Ese código de barras / QR ya existe en este sitio.', 'danger')
            return redirect(url_for('edit_producto', producto_id=producto_id))

        mongo.db.productos.update_one(
            {'_id': ObjectId(producto_id), 'page_id': page_id},
            {'$set': {
                'title': title,
                'description': description,
                'price': money2(price),
                'image': image_path,
                'show_price': show_price,
                'tipo': tipo,
                'sku': sku,
                'barcode': barcode,
                'qr_value': barcode,
                'stock': stock,
                'min_stock': min_stock,
                'track_inventory': track_inventory,
                'active': active,
                'updated_at': datetime.utcnow(),
            }}
        )

        flash('Elemento actualizado correctamente.', 'success')
        return redirect(url_for('list_productos'))

    tipos_posibles = ['producto', 'servicio']
    return render_template('edit_producto.html', producto=producto, tipos_posibles=tipos_posibles)

@app.route('/api/productos/generate-code')
@require_active_subscription
@login_required
def api_generate_producto_code():
    page_id = get_current_page_id()
    if not page_id:
        return {'ok': False, 'message': 'Sitio no seleccionado'}, 400

    title = (request.args.get('title') or '').strip()
    code = generate_product_code(page_id, title)
    return {'ok': True, 'code': code}

from flask import jsonify

@app.route('/api/productos/find-by-code')
@require_active_subscription
@current_site(required=True)
@login_required
def api_find_producto_by_code():
    page_id = get_current_page_id()
    if not page_id:
        return jsonify({
            "ok": False,
            "message": "No hay sitio seleccionado."
        }), 400

    raw_code = (request.args.get('code') or '').strip()
    code = raw_code.upper()

    if not code:
        return jsonify({
            "ok": False,
            "message": "Debes enviar un código."
        }), 400

    producto = mongo.db.productos.find_one({
        "page_id": page_id,
        "active": True,
        "$or": [
            {"barcode": code},
            {"barcode": raw_code},
            {"sku": code},
            {"sku": raw_code}
        ]
    })

    if not producto:
        return jsonify({
            "ok": False,
            "message": f"No se encontró producto con el código: {raw_code}"
        }), 404

    return jsonify({
        "ok": True,
        "producto": {
            "id": str(producto["_id"]),
            "title": producto.get("title", "Producto"),
            "barcode": producto.get("barcode", ""),
            "sku": producto.get("sku", ""),
            "price": float(producto.get("price", 0) or 0),
            "track_inventory": bool(producto.get("track_inventory", False)),
            "stock": int(producto.get("stock", 0) or 0),
            "active": bool(producto.get("active", True))
        }
    }), 200

@app.route('/productos/<producto_id>/qr.png')
@require_active_subscription
@login_required
def producto_qr(producto_id):
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.')
        return redirect(url_for('sites'))

    producto = mongo.db.productos.find_one({
        '_id': ObjectId(producto_id),
        'page_id': page_id
    })

    if not producto:
        flash('Producto no encontrado.', 'warning')
        return redirect(url_for('list_productos'))

    qr_value = producto.get('qr_value') or producto.get('barcode')
    if not qr_value:
        qr_value = generate_product_code(page_id, producto.get('title'))
        mongo.db.productos.update_one(
            {'_id': producto['_id'], 'page_id': page_id},
            {'$set': {
                'barcode': qr_value,
                'qr_value': qr_value,
                'updated_at': datetime.utcnow()
            }}
        )

    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=4
    )
    qr.add_data(qr_value)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype='image/png',
        as_attachment=False,
        download_name=f"{producto.get('title', 'producto')}_qr.png"
    )

@app.route('/productos/<producto_id>/qr-label')
@require_active_subscription
@login_required
def producto_qr_label(producto_id):
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.')
        return redirect(url_for('sites'))

    producto = mongo.db.productos.find_one({
        '_id': ObjectId(producto_id),
        'page_id': page_id
    })

    if not producto:
        flash('Producto no encontrado.', 'warning')
        return redirect(url_for('list_productos'))

    qr_url = url_for('producto_qr', producto_id=producto_id)

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <title>Etiqueta QR</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          background: #f5f7fb;
          padding: 24px;
        }
        .label {
          width: 360px;
          background: white;
          border: 1px solid #dbe3ef;
          border-radius: 18px;
          padding: 20px;
          box-shadow: 0 12px 28px rgba(0,0,0,.08);
        }
        .title {
          font-size: 20px;
          font-weight: 800;
          margin-bottom: 8px;
          color: #111827;
        }
        .sub {
          color: #475467;
          margin-bottom: 14px;
          font-size: 14px;
        }
        .price {
          display: inline-block;
          padding: 8px 14px;
          border-radius: 999px;
          background: #ecfdf3;
          color: #15803d;
          font-weight: 800;
          border: 1px solid #bbf7d0;
          margin-bottom: 16px;
        }
        .code {
          margin-top: 12px;
          font-size: 13px;
          color: #475467;
          word-break: break-all;
        }
        .qr {
          text-align: center;
          margin-top: 10px;
        }
        .qr img {
          max-width: 220px;
          width: 100%;
        }
        .print-btn {
          margin-top: 18px;
          display: inline-block;
          padding: 10px 14px;
          background: #2563eb;
          color: white;
          border-radius: 12px;
          text-decoration: none;
          font-weight: 700;
        }
        @media print {
          .print-btn { display: none; }
          body { background: white; padding: 0; }
          .label { box-shadow: none; border: 1px solid #ccc; }
        }
      </style>
    </head>
    <body>
      <div class="label">
        <div class="title">{{ producto.get('title', 'Producto') }}</div>
        <div class="sub">
          SKU: {{ producto.get('sku') or '—' }}
        </div>

        <div class="price">
          $ {{ '%.2f'|format(producto.get('price', 0)|float) }}
        </div>

        <div class="qr">
          <img src="{{ qr_url }}" alt="QR del producto">
        </div>

        <div class="code">
          Código: {{ producto.get('barcode') or producto.get('qr_value') or '—' }}
        </div>

        <a href="#" onclick="window.print(); return false;" class="print-btn">
          Imprimir etiqueta
        </a>
      </div>
    </body>
    </html>
    """, producto=producto, qr_url=qr_url)

@app.route('/productos/<producto_id>/ensure-code', methods=['POST'])
@require_active_subscription
@login_required
def producto_ensure_code(producto_id):
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.')
        return redirect(url_for('sites'))

    producto = mongo.db.productos.find_one({
        '_id': ObjectId(producto_id),
        'page_id': page_id
    })

    if not producto:
        flash('Producto no encontrado.', 'warning')
        return redirect(url_for('list_productos'))

    barcode = normalize_product_code(producto.get('barcode'))
    if not barcode:
        barcode = generate_product_code(page_id, producto.get('title'))
        mongo.db.productos.update_one(
            {'_id': producto['_id'], 'page_id': page_id},
            {'$set': {
                'barcode': barcode,
                'qr_value': barcode,
                'updated_at': datetime.utcnow()
            }}
        )
        flash('Código generado correctamente.', 'success')
    else:
        flash('Ese producto ya tiene código.', 'info')

    return redirect(url_for('list_productos'))

@app.route('/delete_producto/<producto_id>', methods=['POST'])
@require_active_subscription
@login_required
def delete_producto(producto_id):
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.')
        return redirect(url_for('sites'))

    producto = mongo.db.productos.find_one({
        '_id': ObjectId(producto_id),
        'page_id': page_id
    })

    if not producto:
        flash('Producto no encontrado.')
        return redirect(url_for('list_productos'))

    mongo.db.productos.delete_one({
        '_id': ObjectId(producto_id),
        'page_id': page_id
    })
    flash('Producto eliminado correctamente.')
    return redirect(url_for('list_productos'))

@app.route('/pos', methods=['GET', 'POST'])
@require_active_subscription
@current_site(required=True)
@login_required
def pos():
    page_id = get_current_page_id()

    if request.method == 'POST':
        product_ids = request.form.getlist('producto_id')
        qtys = request.form.getlist('qty')

        items = []
        for pid, qty in zip(product_ids, qtys):
            if pid and parse_int(qty, 0) > 0:
                items.append({
                    'producto_id': pid,
                    'qty': parse_int(qty, 0)
                })

        payment_method = (request.form.get('payment_method') or 'efectivo').strip().lower()
        cash_amount = parse_float(request.form.get('cash_amount'), 0)
        digital_amount = parse_float(request.form.get('digital_amount'), 0)
        customer_name = (request.form.get('customer_name') or '').strip()
        customer_phone = (request.form.get('customer_phone') or '').strip()
        notes = (request.form.get('notes') or '').strip()

        try:
            venta = registrar_venta(
                page_id=page_id,
                items=items,
                payment_method=payment_method,
                cash_amount=cash_amount,
                digital_amount=digital_amount,
                customer_name=customer_name,
                customer_phone=customer_phone,
                notes=notes,
                tipo='mostrador'
            )
            flash(f"Venta registrada correctamente: {venta['folio']}", 'success')
            return redirect(url_for('venta_ticket_pdf', venta_id=str(venta['_id'])))
        except Exception as e:
            flash(str(e), 'danger')
            return redirect(url_for('pos'))

    productos = list(mongo.db.productos.find({
        'page_id': page_id,
        'tipo': 'producto',
        'active': {'$ne': False}
    }).sort('title', 1))

    return render_template('pos.html', productos=productos)

@app.route('/ventas')
@require_active_subscription
@current_site(required=True)
@login_required
def list_ventas():
    page_id = get_current_page_id()

    ventas = list(
        mongo.db.ventas.find({'page_id': page_id}).sort('created_at', -1).limit(300)
    )

    total_ventas = sum(money2(v.get('total', 0)) for v in ventas)

    return render_template(
        'list_ventas.html',
        ventas=ventas,
        total_ventas=money2(total_ventas)
    )

@app.route('/ventas/<venta_id>')
@require_active_subscription
@current_site(required=True)
@login_required
def venta_detail(venta_id):
    page_id = get_current_page_id()
    venta = mongo.db.ventas.find_one({
        '_id': ObjectId(venta_id),
        'page_id': page_id
    })

    if not venta:
        flash('Venta no encontrada.', 'warning')
        return redirect(url_for('list_ventas'))

    return render_template('venta_detail.html', venta=venta)

PAYMENT_LABELS = {
    'efectivo': 'Efectivo',
    'transferencia': 'Transferencia',
    'tarjeta': 'Tarjeta',
    'digital': 'Digital',
    'mixto': 'Mixto',
}


def fmt_money(value):
    try:
        return f"{float(value or 0):,.2f}"
    except Exception:
        return "0.00"


def fmt_dt(dt):
    if not dt:
        return "-"
    try:
        return dt.strftime('%d/%m/%Y %H:%M')
    except Exception:
        return str(dt)


def safe_text(value, fallback='-'):
    text = str(value).strip() if value is not None else ''
    return text or fallback


def wrap_text(text, max_width, font_name="Helvetica", font_size=9):
    text = safe_text(text, '')
    if not text:
        return []

    result = []

    for paragraph in text.splitlines():
        paragraph = paragraph.strip()
        if not paragraph:
            result.append('')
            continue

        words = paragraph.split()
        current = words[0]

        for word in words[1:]:
            test = f"{current} {word}"
            if stringWidth(test, font_name, font_size) <= max_width:
                current = test
            else:
                result.append(current)
                current = word

        result.append(current)

    return result


def draw_wrapped_lines(pdf, lines, x, y, line_height=11, font_name="Helvetica", font_size=9, color=colors.black):
    pdf.setFillColor(color)
    pdf.setFont(font_name, font_size)

    for line in lines:
        pdf.drawString(x, y, line)
        y -= line_height

    return y


def resolve_logo_reader(page):
    """
    Ajusta aquí si en tu BD el campo del logo tiene otro nombre.
    Intenta con:
    - page['logo']
    - page['logo_url']
    - page['business_logo']
    """
    logo_value = (
        page.get('logo')
        or page.get('logo_url')
        or page.get('business_logo')
        or page.get('branding_logo')
    )

    if not logo_value:
        return None

    upload_folder = current_app.config.get('UPLOAD_FOLDER', '')
    candidates = []

    if os.path.isabs(logo_value):
        candidates.append(logo_value)

    if upload_folder:
        candidates.append(os.path.join(upload_folder, logo_value))
        candidates.append(os.path.join(upload_folder, os.path.basename(logo_value)))

    for path in candidates:
        if path and os.path.exists(path):
            try:
                return ImageReader(path)
            except Exception:
                pass

    return None


def estimate_thermal_height(venta):
    items = venta.get('items', []) or []
    notes = safe_text(venta.get('notes'), '')
    customer_name = safe_text(venta.get('customer_name'), '')
    customer_phone = safe_text(venta.get('customer_phone'), '')

    base = 155 * mm
    items_space = max(1, len(items)) * (12 * mm)

    extra = 0
    if notes:
        extra += max(10 * mm, (len(notes) // 34 + 2) * 5 * mm)
    if customer_name:
        extra += 6 * mm
    if customer_phone:
        extra += 6 * mm

    return base + items_space + extra


def draw_logo_centered(pdf, logo_reader, center_x, top_y, max_width, max_height):
    if not logo_reader:
        return top_y

    try:
        iw, ih = logo_reader.getSize()
        if iw <= 0 or ih <= 0:
            return top_y

        scale = min(max_width / iw, max_height / ih)
        draw_w = iw * scale
        draw_h = ih * scale
        x = center_x - (draw_w / 2)

        pdf.drawImage(
            logo_reader,
            x,
            top_y - draw_h,
            width=draw_w,
            height=draw_h,
            preserveAspectRatio=True,
            mask='auto'
        )
        return top_y - draw_h
    except Exception:
        return top_y


def draw_letter_header(pdf, page, venta, business_name, width, height):
    accent = colors.HexColor("#1d4ed8")
    dark = colors.HexColor("#0f172a")
    muted = colors.HexColor("#64748b")
    soft = colors.HexColor("#e2e8f0")

    margin_x = 42
    content_w = width - (margin_x * 2)
    y = height - 38

    logo_reader = resolve_logo_reader(page)
    if logo_reader:
        y = draw_logo_centered(pdf, logo_reader, width / 2, y, max_width=120, max_height=46)
        y -= 10

    pdf.setFillColor(dark)
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawCentredString(width / 2, y, business_name)
    y -= 20

    phone = page.get('phone') or page.get('business_phone') or page.get('whatsapp') or ''
    address = page.get('address') or page.get('business_address') or ''
    header_meta = " · ".join([v for v in [safe_text(phone, ''), safe_text(address, '')] if v])

    if header_meta:
        pdf.setFillColor(muted)
        pdf.setFont("Helvetica", 9)
        pdf.drawCentredString(width / 2, y, header_meta)
        y -= 16

    pdf.setStrokeColor(accent)
    pdf.setLineWidth(1.2)
    pdf.line(margin_x, y, width - margin_x, y)
    y -= 18

    # Caja de datos
    box_h = 66
    pdf.setFillColor(colors.white)
    pdf.setStrokeColor(soft)
    pdf.roundRect(margin_x, y - box_h, content_w, box_h, 10, fill=1, stroke=1)

    pdf.setFillColor(muted)
    pdf.setFont("Helvetica-Bold", 8)
    pdf.drawString(margin_x + 14, y - 16, "FOLIO")
    pdf.drawString(margin_x + 170, y - 16, "FECHA")
    pdf.drawString(margin_x + 360, y - 16, "CLIENTE")

    pdf.setFillColor(dark)
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(margin_x + 14, y - 32, safe_text(venta.get('folio'), 'SIN FOLIO'))

    pdf.setFont("Helvetica", 10)
    pdf.drawString(margin_x + 170, y - 32, fmt_dt(venta.get('created_at')))
    pdf.drawString(margin_x + 360, y - 32, safe_text(venta.get('customer_name'), 'Mostrador'))

    pdf.setFillColor(muted)
    pdf.setFont("Helvetica-Bold", 8)
    pdf.drawString(margin_x + 14, y - 48, "TELÉFONO")

    pdf.setFillColor(dark)
    pdf.setFont("Helvetica", 10)
    pdf.drawString(margin_x + 14, y - 62, safe_text(venta.get('customer_phone'), '-'))

    return y - box_h - 18


def draw_letter_items_header(pdf, margin_x, y, width):
    dark = colors.HexColor("#0f172a")
    accent = colors.HexColor("#eff6ff")
    line = colors.HexColor("#dbe5f1")

    pdf.setFillColor(accent)
    pdf.setStrokeColor(line)
    pdf.roundRect(margin_x, y - 20, width, 20, 8, fill=1, stroke=1)

    pdf.setFillColor(dark)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawString(margin_x + 10, y - 13, "CANT.")
    pdf.drawString(margin_x + 58, y - 13, "PRODUCTO")
    pdf.drawRightString(margin_x + width - 90, y - 13, "P/U")
    pdf.drawRightString(margin_x + width - 14, y - 13, "IMPORTE")

    return y - 28


def build_letter_ticket(pdf, venta, page, business_name):
    width, height = letter
    margin_x = 42
    content_w = width - (margin_x * 2)
    dark = colors.HexColor("#0f172a")
    muted = colors.HexColor("#64748b")
    soft = colors.HexColor("#e2e8f0")
    accent = colors.HexColor("#1d4ed8")
    green = colors.HexColor("#15803d")

    y = draw_letter_header(pdf, page, venta, business_name, width, height)
    y = draw_letter_items_header(pdf, margin_x, y, content_w)

    items = venta.get('items', []) or []

    for item in items:
        qty = item.get('qty', 0)
        title = safe_text(item.get('title'), 'Producto')
        unit_price = float(item.get('unit_price', 0) or 0)
        subtotal = float(item.get('subtotal', 0) or 0)

        lines = wrap_text(title, max_width=content_w - 185, font_name="Helvetica", font_size=9)
        row_h = max(22, 12 + (len(lines) * 11))

        if y - row_h < 120:
            pdf.showPage()
            y = height - 50
            pdf.setStrokeColor(accent)
            pdf.setLineWidth(1)
            pdf.line(margin_x, y, width - margin_x, y)
            y -= 18
            pdf.setFillColor(dark)
            pdf.setFont("Helvetica-Bold", 14)
            pdf.drawString(margin_x, y, f"Ticket {safe_text(venta.get('folio'), 'SIN FOLIO')} - Continuación")
            y -= 18
            y = draw_letter_items_header(pdf, margin_x, y, content_w)

        pdf.setStrokeColor(soft)
        pdf.line(margin_x, y - row_h + 6, margin_x + content_w, y - row_h + 6)

        pdf.setFillColor(dark)
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawString(margin_x + 10, y - 6, str(qty))

        current_y = y - 6
        pdf.setFont("Helvetica", 9)
        for line in lines:
            pdf.drawString(margin_x + 58, current_y, line)
            current_y -= 11

        pdf.setFont("Helvetica", 9)
        pdf.drawRightString(margin_x + content_w - 90, y - 6, f"${fmt_money(unit_price)}")
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawRightString(margin_x + content_w - 14, y - 6, f"${fmt_money(subtotal)}")

        y -= row_h

    y -= 8

    # Totales
    totals_w = 220
    totals_x = width - margin_x - totals_w

    pdf.setFillColor(colors.white)
    pdf.setStrokeColor(soft)
    pdf.roundRect(totals_x, y - 82, totals_w, 82, 10, fill=1, stroke=1)

    pdf.setFillColor(muted)
    pdf.setFont("Helvetica", 9)
    pdf.drawString(totals_x + 14, y - 18, "Subtotal")
    pdf.drawRightString(totals_x + totals_w - 14, y - 18, f"${fmt_money(venta.get('subtotal', 0))}")

    pdf.drawString(totals_x + 14, y - 34, "Descuento")
    pdf.drawRightString(totals_x + totals_w - 14, y - 34, f"${fmt_money(venta.get('discount', 0))}")

    pdf.setStrokeColor(soft)
    pdf.line(totals_x + 14, y - 44, totals_x + totals_w - 14, y - 44)

    pdf.setFillColor(dark)
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(totals_x + 14, y - 62, "TOTAL")
    pdf.setFillColor(green)
    pdf.drawRightString(totals_x + totals_w - 14, y - 62, f"${fmt_money(venta.get('total', 0))}")

    y -= 104

    # Pago / notas
    pay_label = PAYMENT_LABELS.get(venta.get('payment_method'), safe_text(venta.get('payment_method')))
    pdf.setFillColor(dark)
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(margin_x, y, "Detalle de pago")
    y -= 16

    pdf.setFont("Helvetica", 9)
    pdf.setFillColor(muted)
    pdf.drawString(margin_x, y, f"Método: {pay_label}")
    y -= 13
    pdf.drawString(margin_x, y, f"Efectivo: ${fmt_money(venta.get('cash_amount', 0))}")
    y -= 13
    pdf.drawString(margin_x, y, f"Digital: ${fmt_money(venta.get('digital_amount', 0))}")
    y -= 18

    notes = safe_text(venta.get('notes'), '')
    if notes:
        pdf.setFillColor(dark)
        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(margin_x, y, "Notas")
        y -= 14

        note_lines = wrap_text(notes, max_width=content_w, font_name="Helvetica", font_size=9)
        y = draw_wrapped_lines(
            pdf,
            note_lines,
            margin_x,
            y,
            line_height=11,
            font_name="Helvetica",
            font_size=9,
            color=muted
        )
        y -= 8

    pdf.setStrokeColor(soft)
    pdf.line(margin_x, y, width - margin_x, y)
    y -= 18

    pdf.setFillColor(muted)
    pdf.setFont("Helvetica-Oblique", 9)
    pdf.drawCentredString(width / 2, y, "Gracias por tu compra")


def build_thermal_ticket(pdf, venta, page, business_name, page_size):
    width, height = page_size
    margin_x = 6 * mm
    content_w = width - (margin_x * 2)
    center_x = width / 2

    dark = colors.HexColor("#111827")
    muted = colors.HexColor("#6b7280")
    soft = colors.HexColor("#d1d5db")
    green = colors.HexColor("#166534")

    y = height - 8 * mm

    logo_reader = resolve_logo_reader(page)
    if logo_reader:
        y = draw_logo_centered(pdf, logo_reader, center_x, y, max_width=34 * mm, max_height=18 * mm)
        y -= 3 * mm

    pdf.setFillColor(dark)
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawCentredString(center_x, y, business_name[:34])
    y -= 5 * mm

    phone = page.get('phone') or page.get('business_phone') or page.get('whatsapp') or ''
    address = page.get('address') or page.get('business_address') or ''
    meta = [v for v in [safe_text(phone, ''), safe_text(address, '')] if v]

    pdf.setFont("Helvetica", 7.5)
    pdf.setFillColor(muted)
    for row in meta[:2]:
        lines = wrap_text(row, content_w, "Helvetica", 7.5)
        for line in lines[:2]:
            pdf.drawCentredString(center_x, y, line)
            y -= 4 * mm

    pdf.setStrokeColor(soft)
    pdf.line(margin_x, y, width - margin_x, y)
    y -= 5 * mm

    pdf.setFillColor(dark)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawCentredString(center_x, y, f"TICKET {safe_text(venta.get('folio'), 'SIN FOLIO')}")
    y -= 5 * mm

    pdf.setFillColor(muted)
    pdf.setFont("Helvetica", 7.5)
    pdf.drawString(margin_x, y, f"Fecha: {fmt_dt(venta.get('created_at'))}")
    y -= 4.5 * mm
    pdf.drawString(margin_x, y, f"Cliente: {safe_text(venta.get('customer_name'), 'Mostrador')}")
    y -= 4.5 * mm
    pdf.drawString(margin_x, y, f"Tel: {safe_text(venta.get('customer_phone'), '-')}")
    y -= 5 * mm

    pdf.setStrokeColor(soft)
    pdf.line(margin_x, y, width - margin_x, y)
    y -= 4 * mm

    items = venta.get('items', []) or []
    for item in items:
        qty = item.get('qty', 0)
        title = safe_text(item.get('title'), 'Producto')
        unit_price = float(item.get('unit_price', 0) or 0)
        subtotal = float(item.get('subtotal', 0) or 0)

        title_lines = wrap_text(f"{qty} x {title}", content_w, "Helvetica-Bold", 8)
        pdf.setFillColor(dark)
        pdf.setFont("Helvetica-Bold", 8)
        for line in title_lines:
            pdf.drawString(margin_x, y, line)
            y -= 4 * mm

        pdf.setFillColor(muted)
        pdf.setFont("Helvetica", 7.5)
        pdf.drawString(margin_x, y, f"P/U: ${fmt_money(unit_price)}")
        pdf.drawRightString(width - margin_x, y, f"${fmt_money(subtotal)}")
        y -= 5 * mm

    pdf.setStrokeColor(soft)
    pdf.line(margin_x, y, width - margin_x, y)
    y -= 5 * mm

    pdf.setFillColor(muted)
    pdf.setFont("Helvetica", 8)
    pdf.drawString(margin_x, y, "Subtotal")
    pdf.drawRightString(width - margin_x, y, f"${fmt_money(venta.get('subtotal', 0))}")
    y -= 4.5 * mm

    pdf.drawString(margin_x, y, "Descuento")
    pdf.drawRightString(width - margin_x, y, f"${fmt_money(venta.get('discount', 0))}")
    y -= 5 * mm

    pdf.setFillColor(dark)
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(margin_x, y, "TOTAL")
    pdf.setFillColor(green)
    pdf.drawRightString(width - margin_x, y, f"${fmt_money(venta.get('total', 0))}")
    y -= 6 * mm

    pay_label = PAYMENT_LABELS.get(venta.get('payment_method'), safe_text(venta.get('payment_method')))

    pdf.setFillColor(muted)
    pdf.setFont("Helvetica", 7.5)
    pdf.drawString(margin_x, y, f"Método: {pay_label}")
    y -= 4.5 * mm
    pdf.drawString(margin_x, y, f"Efectivo: ${fmt_money(venta.get('cash_amount', 0))}")
    y -= 4.5 * mm
    pdf.drawString(margin_x, y, f"Digital: ${fmt_money(venta.get('digital_amount', 0))}")
    y -= 5 * mm

    notes = safe_text(venta.get('notes'), '')
    if notes:
        pdf.setStrokeColor(soft)
        pdf.line(margin_x, y, width - margin_x, y)
        y -= 4.5 * mm

        pdf.setFillColor(dark)
        pdf.setFont("Helvetica-Bold", 8)
        pdf.drawString(margin_x, y, "Notas")
        y -= 4.5 * mm

        note_lines = wrap_text(notes, content_w, "Helvetica", 7.5)
        pdf.setFillColor(muted)
        pdf.setFont("Helvetica", 7.5)
        for line in note_lines:
            pdf.drawString(margin_x, y, line)
            y -= 4 * mm

        y -= 2 * mm

    pdf.setStrokeColor(soft)
    pdf.line(margin_x, y, width - margin_x, y)
    y -= 6 * mm

    pdf.setFillColor(dark)
    pdf.setFont("Helvetica-Bold", 8.5)
    pdf.drawCentredString(center_x, y, "¡Gracias por tu compra!")
    y -= 4.5 * mm

    pdf.setFillColor(muted)
    pdf.setFont("Helvetica", 7)
    pdf.drawCentredString(center_x, y, "Conserva este comprobante")


@app.route('/ventas/<venta_id>/ticket.pdf')
@require_active_subscription
@current_site(required=True)
@login_required
def venta_ticket_pdf(venta_id):
    page_id = get_current_page_id()

    venta = mongo.db.ventas.find_one({
        '_id': ObjectId(venta_id),
        'page_id': page_id
    })

    if not venta:
        flash('Venta no encontrada.', 'warning')
        return redirect(url_for('list_ventas'))

    page = mongo.db.page_data.find_one({'_id': page_id}) or {}
    business_name = page.get('business_name', 'Mi negocio')

    paper = (request.args.get('paper') or 'letter').strip().lower()
    if paper not in ('letter', 'thermal'):
        paper = 'letter'

    buffer = BytesIO()

    if paper == 'thermal':
        page_size = (80 * mm, estimate_thermal_height(venta))
        pdf = canvas.Canvas(buffer, pagesize=page_size)
        pdf.setTitle(f"Ticket {safe_text(venta.get('folio'), 'ticket')}")
        build_thermal_ticket(pdf, venta, page, business_name, page_size)
        filename = f'{safe_text(venta.get("folio"), "ticket")}_thermal.pdf'
    else:
        pdf = canvas.Canvas(buffer, pagesize=letter)
        pdf.setTitle(f"Ticket {safe_text(venta.get('folio'), 'ticket')}")
        build_letter_ticket(pdf, venta, page, business_name)
        filename = f'{safe_text(venta.get("folio"), "ticket")}_letter.pdf'

    pdf.showPage()
    pdf.save()

    buffer.seek(0)
    return Response(
        buffer.getvalue(),
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'inline; filename={filename}'
        }
    )

@app.route('/corte-caja')
@require_active_subscription
@current_site(required=True)
@login_required
def corte_caja():
    page_id = get_current_page_id()
    date_str = (request.args.get('date') or datetime.utcnow().strftime('%Y-%m-%d')).strip()

    try:
        start = datetime.strptime(date_str + ' 00:00:00', '%Y-%m-%d %H:%M:%S')
        end = datetime.strptime(date_str + ' 23:59:59', '%Y-%m-%d %H:%M:%S')
    except Exception:
        flash('Fecha inválida. Usa YYYY-MM-DD.', 'warning')
        return redirect(url_for('corte_caja'))

    ventas = list(mongo.db.ventas.find({
        'page_id': page_id,
        'status': 'paid',
        'created_at': {'$gte': start, '$lte': end}
    }).sort('created_at', -1))

    total = money2(sum(money2(v.get('total', 0)) for v in ventas))
    efectivo = money2(sum(money2(v.get('cash_amount', 0)) for v in ventas))
    digital = money2(sum(money2(v.get('digital_amount', 0)) for v in ventas))
    tickets = len(ventas)
    promedio = money2(total / tickets) if tickets else 0.0

    return render_template(
        'corte_caja.html',
        ventas=ventas,
        fecha=date_str,
        total=total,
        efectivo=efectivo,
        digital=digital,
        tickets=tickets,
        promedio=promedio
    )

@app.route('/admin/users')
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required('admin')
def manage_users():
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    except Exception as e:
        flash("Error al obtener usuario.")
        return redirect(url_for('login'))
    
    if current_user.role != 'admin':
        flash('Acceso denegado.')
        return redirect(url_for('dashboard'))
    
    page_id = user.get('page_id')
    users = mongo.db.users.find({'page_id': page_id})
    return render_template('manage_users.html', users=users)

@app.route('/admin/users/edit/<user_id>', methods=['GET', 'POST'])
@require_active_subscription
@login_required
@roles_required('admin')
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Acceso denegado.')
        return redirect(url_for('dashboard'))

    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})

    if request.method == 'POST':
        new_role = request.form['role']
        confirmed = request.form.get('confirmed') == 'on'

        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {
            '$set': {
                'role': new_role,
                'confirmed': confirmed
            }
        })

        flash('Usuario actualizado correctamente.')
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user)

@app.route('/admin/users/delete/<user_id>', methods=['GET'])
@login_required
@roles_required('admin')
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Acceso denegado.')
        return redirect(url_for('dashboard'))

    mongo.db.users.delete_one({'_id': ObjectId(user_id)})
    flash('Usuario eliminado correctamente.')
    return redirect(url_for('manage_users'))

import json

MP_PREFS_URL = "https://api.mercadopago.com/checkout/preferences"
MP_PAYMENTS_URL = "https://api.mercadopago.com/v1/payments/"

def mp_headers():
    token = os.getenv('MP_ACCESS_TOKEN')
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


def mp_patch_preapproval_status(preapproval_id: str, new_status: str):
    """Hace PATCH al preapproval para cambiar su estado."""
    url = f"{MP_PREAPPROVALS_URL}/{preapproval_id}"
    payload = {"status": new_status}
    r = requests.put(url, headers=mp_headers(), json=payload)  # MP acepta PUT/PATCH (usa PUT aquí)
    return r

# --- helpers para PATCH de preapproval ---
def mp_update_preapproval_status(preapproval_id: str, new_status: str):
    """
    new_status: 'paused' | 'authorized' | 'cancelled'
    """
    body = {"status": new_status}
    r = requests.patch(f"{MP_PREAPPROVALS_URL}/{preapproval_id}",
                       headers=mp_headers(),
                       data=json.dumps(body))
    # lanza si hay error HTTP
    r.raise_for_status()
    return r.json()

@app.route('/subscription/<action>', methods=['POST'])
@login_required
def subscription_action(action):
    """
    action in {'pause','resume','cancel'}
    """
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.', 'warning')
        return redirect(url_for('sites'))

    sub = mongo.db.subscriptions.find_one({"page_id": page_id})
    if not sub or not sub.get('preapproval_id'):
        flash('No hay suscripción registrada para este sitio.', 'warning')
        return redirect(url_for('billing_portal'))

    mapping = {
        "pause": "paused",
        "resume": "authorized",   # vuelve a quedar “autorizada”
        "cancel": "cancelled"
    }
    if action not in mapping:
        flash('Acción inválida.', 'danger')
        return redirect(url_for('billing_portal'))

    new_status = mapping[action]

    try:
        # PATCH a Mercado Pago
        mp_resp = mp_update_preapproval_status(sub['preapproval_id'], new_status)

        # Refrescar estado desde MP (opcional pero recomendable)
        pre = requests.get(f"{MP_PREAPPROVALS_URL}/{sub['preapproval_id']}", headers=mp_headers()).json()

        mongo.db.subscriptions.update_one(
            {"_id": sub["_id"]},
            {"$set": {
                "status": pre.get("status", new_status),
                "raw": pre,
                "last_event": datetime.utcnow()
            }}
        )

        if action == "pause":
            flash("Tu suscripción fue pausada.", "success")
        elif action == "resume":
            flash("Tu suscripción fue reanudada.", "success")
        elif action == "cancel":
            flash("Tu suscripción fue cancelada.", "success")

    except requests.HTTPError as e:
        print("MP PATCH error:", e.response.text if e.response else e)
        flash("No se pudo actualizar la suscripción en Mercado Pago.", "danger")
    except Exception as e:
        print("Subscription action error:", e)
        flash("Ocurrió un error al procesar la acción.", "danger")

    return redirect(url_for('billing_portal'))

def migrate_users_page_ids():
    # Llama esto 1 vez al iniciar la app (después de init mongo)
    for u in mongo.db.users.find({}):
        updates = {}
        legacy = u.get('page_id')
        page_ids = u.get('page_ids') or []
        curr = u.get('current_page_id')

        # normaliza a ObjectId
        def as_oid(v):
            try:
                return ObjectId(v) if isinstance(v, str) else v
            except:
                return None

        page_ids = [as_oid(x) for x in page_ids if as_oid(x)]
        legacy_oid = as_oid(legacy)
        curr_oid = as_oid(curr)

        if legacy_oid and legacy_oid not in page_ids:
            page_ids.append(legacy_oid)
            updates['page_ids'] = page_ids
        if not curr_oid and legacy_oid:
            updates['current_page_id'] = legacy_oid

        if updates:
            mongo.db.users.update_one({'_id': u['_id']}, {'$set': updates})

migrate_users_page_ids()

@app.route('/mp/webhook', methods=['POST', 'GET'])
def mp_webhook():
    try:
        # MP puede mandar info por query o por JSON body
        data = request.get_json(silent=True) or {}
        query = request.args.to_dict()

        payment_id = (
            (data.get('data') or {}).get('id') or
            query.get('data.id') or
            data.get('id') or
            query.get('id')
        )
        type_ = data.get('type') or query.get('type') or query.get('topic')

        if type_ != 'payment' or not payment_id:
            return "ignored", 200

        # Consulta del pago
        pay_r = requests.get(MP_PAYMENTS_URL + str(payment_id), headers=mp_headers())
        pay = pay_r.json()

        status = pay.get('status')
        external_reference = pay.get('external_reference', '')
        # external_reference: "<user_id>|<page_id>|<addon_slug>"
        try:
            uid, page_id, addon_slug = external_reference.split('|', 2)
        except:
            uid, page_id, addon_slug = None, None, None

        # Guardamos registro de pago
        mongo.db.purchases.update_one(
            {"provider": "mercado_pago", "mp_payment_id": str(payment_id)},
            {"$set": {
                "provider": "mercado_pago",
                "mp_payment_id": str(payment_id),
                "status": status,
                "amount": (pay.get('transaction_amount') or 0),
                "currency": pay.get('currency_id'),
                "payer": (pay.get('payer') or {}),
                "external_reference": external_reference,
                "addon_slug": addon_slug,
                "page_id": ObjectId(page_id) if page_id else None,
                "user_id": ObjectId(uid) if uid else None,
                "paid_at": datetime.utcnow()
            }},
            upsert=True
        )

        return "ok", 200
    except Exception as e:
        print("Webhook error:", e)
        return "error", 500

@app.route('/mp/success')
def mp_success():
    flash('Pago recibido. Si no ves cambios inmediatos, se aplicarán en segundos. 🎉')
    return redirect(url_for('dashboard'))

@app.route('/mp/failure')
def mp_failure():
    flash('El pago no se completó. Puedes intentar de nuevo.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/checkout/addon/<slug>')
@login_required
def checkout_addon(slug):
    page_id = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}).get('page_id')
    addon = mongo.db.addons.find_one({"slug": slug, "enabled": True})
    if not addon:
        flash('Add-on no disponible.')
        return redirect(url_for('dashboard'))

    payload = {
        "items": [{
            "title": addon['name'],
            "quantity": 1,
            "currency_id": "MXN",
            "unit_price": int(addon['price_mxn'])
        }],
        "auto_return": "approved",
        "back_urls": {
            "success": os.getenv("MP_SUCCESS_URL"),
            "failure": os.getenv("MP_FAILURE_URL"),
            "pending": os.getenv("MP_SUCCESS_URL")
        },
        "notification_url": os.getenv("MP_WEBHOOK_URL"),
        "external_reference": f"{current_user.id}|{page_id}|{slug}"
    }
    r = requests.post(MP_PREFS_URL, headers=mp_headers(), data=json.dumps(payload))
    pref = r.json()
    return redirect(pref.get("init_point") or pref.get("sandbox_init_point") or url_for('dashboard'))

@app.route('/create_page', methods=['GET', 'POST'])
def create_page():
    if request.method == 'POST':
        business_name  = request.form.get('business_name', '').strip()
        description    = request.form.get('description', '').strip()
        category       = request.form.get('category', '').strip()
        slogan         = request.form.get('slogan', '').strip()
        founding_date  = request.form.get('founding_date', '').strip()

        # Contacto y ubicación
        phone         = request.form.get('phone', '').strip()
        whatsapp      = request.form.get('whatsapp', '').strip()
        email_contact = request.form.get('email', '').strip()
        website       = request.form.get('website', '').strip()
        address       = request.form.get('address', '').strip()
        postal_code   = request.form.get('postal_code', '').strip()
        city          = request.form.get('city', '').strip()
        state         = request.form.get('state', '').strip()
        color         = request.form.get('color', '').strip()

        # Coordenadas (opcionales)
        lat = request.form.get('lat')
        lng = request.form.get('lng')

        # Redes
        facebook  = request.form.get('facebook', '').strip()
        instagram = request.form.get('instagram', '').strip()
        tiktok    = request.form.get('tiktok', '').strip()

        # Operación y servicios
        operating_hours     = request.form.get('operating_hours', '').strip()
        services            = request.form.get('services', '').strip()
        payment_methods     = request.form.get('payment_methods', '').strip()
        delivery_available  = request.form.get('delivery_available') == 'on'

        # Validación mínima
        if not business_name or not description or not category or not state:
            flash('Completa los campos obligatorios (nombre, descripción, categoría, estado).', 'warning')
            return redirect(url_for('create_page'))

        # Imagen (opcional)
        image = request.files.get('image')
        image_path = None
        if image and image.filename:
            slug_empresa = slugify(business_name)
            today = datetime.utcnow().strftime('%Y-%m-%d')
            folder_path = os.path.join(app.config['UPLOAD_FOLDER'], slug_empresa, today)
            os.makedirs(folder_path, exist_ok=True)

            filename = secure_filename(image.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            final_filename = f"{timestamp}_{filename}"
            full_path = os.path.join(folder_path, final_filename)
            image.save(full_path)

            image_path = f"{slug_empresa}/{today}/{final_filename}"

        def _safe_float(v):
            try:
                return float(v)
            except Exception:
                return None

        # Slug único desde el inicio
        page_slug = unique_slug_for_page(business_name)

        # ✅ FREE TRIAL automático
        trial_until = datetime.utcnow() + timedelta(days=get_trial_days())

        new_page = {
            'business_name':  business_name,
            'description':    description,
            'category':       category,
            'slogan':         slogan,
            'founding_date':  founding_date,
            'phone':          phone,
            'whatsapp':       whatsapp,
            'email':          email_contact,
            'website':        website,
            'address':        address,
            'postal_code':    postal_code,
            'city':           city,
            'state':          state,
            'color':          color,
            'lat':            _safe_float(lat),
            'lng':            _safe_float(lng),
            'facebook':       facebook,
            'instagram':      instagram,
            'tiktok':         tiktok,
            'operating_hours': operating_hours,
            'services':        services,
            'payment_methods': payment_methods,
            'delivery_available': delivery_available,
            'image':            image_path,
            'slug':             page_slug,
            'default_html':     'classico',

            # ✅ TRIAL
            'trial_until': trial_until,
            'plan': 'trial'
        }

        result = mongo.db.page_data.insert_one(new_page)
        page_id = result.inserted_id

        # Si el usuario está logueado, asociamos el sitio y vamos a Facturación
        if current_user.is_authenticated:
            try:
                ensure_user_page_lists(current_user.id, page_id)
            except Exception:
                u = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
                page_ids = u.get('page_ids') or []
                if ObjectId(page_id) not in [ObjectId(str(x)) for x in page_ids]:
                    page_ids.append(ObjectId(page_id))
                mongo.db.users.update_one(
                    {'_id': ObjectId(current_user.id)},
                    {'$set': {'page_ids': page_ids, 'current_page_id': ObjectId(page_id)}}
                )

            set_current_page_id(page_id)
            flash(f'Empresa creada ✅ Tienes prueba gratis por {get_trial_days()} días.', 'success')
            return redirect(url_for('billing_portal'))

        # Si NO está logueado, lo mandamos a crear su usuario admin
        flash('Empresa creada ✅ Crea tu usuario administrador para continuar.', 'success')
        return redirect(url_for('register', page_id=str(page_id)))

    # GET
    return render_template('create_page.html')

@app.route('/sites')
@login_required
def sites():
    u = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    ids = set()

    def add(v):
        try:
            if v: ids.add(ObjectId(str(v)))
        except:
            pass

    for pid in (u.get('page_ids') or []):
        add(pid)
    add(u.get('page_id'))  # legacy

    pages = list(mongo.db.page_data.find({'_id': {'$in': list(ids)}}))

    # 💡 Backfill de slug si faltara (para sitios antiguos)
    for p in pages:
        if not p.get('slug'):
            new_slug = unique_slug_for_page(p.get('business_name', 'sitio'))
            mongo.db.page_data.update_one({'_id': p['_id']}, {'$set': {'slug': new_slug}})
            p['slug'] = new_slug

    current = str(get_current_page_id() or '')
    return render_template('sites.html', pages=pages, current=current)

@app.route('/sites/switch/<site_id>')
@login_required
def switch_site(site_id):
    def as_oid(v):
        try:
            return ObjectId(str(v))
        except:
            return None

    target = as_oid(site_id)
    if not target:
        flash('ID de sitio inválido.')
        return redirect(url_for('sites'))

    u = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    owned = set()
    for pid in (u.get('page_ids') or []):
        op = as_oid(pid)
        if op: owned.add(op)
    # incluye legacy
    op = as_oid(u.get('page_id'))
    if op: owned.add(op)

    if target not in owned:
        flash('No puedes acceder a ese sitio.')
        return redirect(url_for('sites'))

    set_current_page_id(target)
    flash('Sitio activo cambiado.')
    return redirect(url_for('dashboard'))

DEFAULT_HTML_TEMPLATES = {
    "classico": "themes/classico/site.html",
    "belleza_mujer": "themes/belleza_mujer/site.html",
    "barber_shop": "themes/barber_shop/site.html",
}

# =========================================================
# THEME PACKS: un tema controla varias vistas del sitio
# =========================================================

DEFAULT_THEME_KEY = "classico"

THEME_VIEWS = {
    "classico": {
        "site": "themes/classico/site.html",
        "blog_index": "themes/classico/blog_index.html",
        "blog_post": "themes/classico/blog_post.html",
    },
    "belleza_mujer": {
        "site": "themes/belleza_mujer/site.html",
        "blog_index": "themes/belleza_mujer/blog_index.html",
        "blog_post": "themes/belleza_mujer/blog_post.html",
    },
    "barber_shop": {
        "site": "themes/barber_shop/site.html",
        "blog_index": "themes/barber_shop/blog_index.html",
        "blog_post": "themes/barber_shop/blog_post.html",
    },
}

def get_theme_key(page_doc):
    if not page_doc:
        return DEFAULT_THEME_KEY
    return (page_doc.get("default_html") or DEFAULT_THEME_KEY).strip()

def get_theme_view(page_doc, view_type):
    theme_key = get_theme_key(page_doc)
    pack = THEME_VIEWS.get(theme_key) or THEME_VIEWS[DEFAULT_THEME_KEY]
    return pack.get(view_type) or THEME_VIEWS[DEFAULT_THEME_KEY][view_type]

@app.route('/manage_page')
@require_active_subscription
@login_required
def manage_page_compat():
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.')
        return redirect(url_for('sites'))
    page = mongo.db.page_data.find_one({'_id': page_id})
    if not page:
        flash('Sitio no encontrado.')
        return redirect(url_for('sites'))
    page = ensure_page_has_slug(page)
    return redirect(url_for('manage_page_slug', slug=page['slug']))

@app.route('/negocio/<nombre>/media/delete', methods=['POST'])
def borrar_media(nombre):
    negocio = mongo.db.page_data.find_one({'business_name': nombre})
    if not negocio:
        flash('Negocio no encontrado.')
        return redirect(url_for('index'))

    media_path = request.form.get('path')   # viene del form
    # puede venir, pero ya no lo vamos a usar para filtrar:
    # media_type = request.form.get('type')

    if not media_path:
        flash('No se indicó el archivo a borrar.')
        return redirect(url_for('detalle_negocio', nombre=nombre))

    # helper para quedarnos con el nombre real aunque venga URL completa
    def _basename(p: str) -> str:
        parsed = urlparse(p)
        if parsed.scheme and parsed.path:
            return os.path.basename(parsed.path)
        return os.path.basename(p)

    clean_name = _basename(media_path)

    # =============================
    # 1) Intento 1: borrar por path EXACTO
    # =============================
    res1 = mongo.db.page_data.update_one(
        {'_id': negocio['_id']},
        {
            '$pull': {
                'media_gallery': {
                    'path': media_path  # sin checar type
                }
            }
        }
    )

    # =============================
    # 2) Intento 2: borrar por basename
    #    (por si en la BD se guardó solo el nombre)
    # =============================
    if res1.modified_count == 0 and clean_name != media_path:
        mongo.db.page_data.update_one(
            {'_id': negocio['_id']},
            {
                '$pull': {
                    'media_gallery': {
                        'path': clean_name
                    }
                }
            }
        )

    # =============================
    # 3) Borrar archivo físico (opcional)
    # =============================
    upload_dir = app.config.get('UPLOAD_FOLDER', 'uploads')
    file_abs_path = os.path.join(upload_dir, clean_name)
    try:
        if os.path.exists(file_abs_path):
            os.remove(file_abs_path)
    except Exception as e:
        app.logger.warning(f"No se pudo borrar archivo {file_abs_path}: {e}")

    flash('Archivo de galería eliminado ✅')

    # sacar el slug del negocio para regresar al admin
    slug = negocio.get('slug')
    if slug:
        return redirect(url_for('manage_page_slug', slug=slug))
    else:
        return redirect(url_for('detalle_negocio', nombre=nombre))


def get_page_booking_settings(page_id: ObjectId):
    page = mongo.db.page_data.find_one(
        {"_id": ObjectId(page_id)},
        {"booking_enabled": 1, "booking_slot_minutes": 1, "booking_open": 1, "booking_close": 1, "booking_days": 1}
    ) or {}

    enabled = bool(page.get("booking_enabled", True))
    slot = int(page.get("booking_slot_minutes", 30) or 30)
    open_h = (page.get("booking_open") or "10:00").strip()
    close_h = (page.get("booking_close") or "19:00").strip()
    days = page.get("booking_days")
    if not isinstance(days, list) or not days:
        days = [0,1,2,3,4,5]  # Lun-Sáb

    return {"enabled": enabled, "slot": slot, "open": open_h, "close": close_h, "days": days}

def parse_hhmm(hhmm: str):
    # "10:30" -> (10,30)
    try:
        h, m = hhmm.split(":")
        return int(h), int(m)
    except:
        return 10, 0

def dt_at(date_obj: date, hhmm: str):
    h, m = parse_hhmm(hhmm)
    return datetime(date_obj.year, date_obj.month, date_obj.day, h, m)

def overlaps(a_start, a_end, b_start, b_end):
    return a_start < b_end and b_start < a_end

@app.route('/manage_page/<slug>', methods=['GET', 'POST'])
@login_required
@require_active_subscription
@roles_required('admin')
def manage_page_slug(slug):
    if current_user.role != 'admin':
        flash('Acceso denegado.')
        return redirect(url_for('dashboard'))

    page = get_page_by_slug(slug)
    if not page:
        flash('Sitio no encontrado.')
        return redirect(url_for('sites'))

    # fija el sitio activo por conveniencia
    set_current_page_id(page['_id'])
    page = ensure_page_has_slug(page)

    if request.method == 'POST':
        # --- Información básica
        business_name = request.form['business_name']
        description   = request.form['description']
        category      = request.form['category']
        slogan        = request.form['slogan']
        founding_date = request.form['founding_date']

        # --- Contacto y ubicación
        phone       = request.form['phone']
        whatsapp    = request.form['whatsapp']
        email       = request.form['email']
        website     = request.form['website']
        address     = request.form.get('address')
        postal_code = request.form['postal_code']
        city        = request.form['city']
        state       = request.form['state']
        color       = request.form['color']
        lat_raw     = request.form.get('lat')
        lng_raw     = request.form.get('lng')

        def _safe_float(v):
            try:
                return float(v)
            except:
                return None

        lat = _safe_float(lat_raw) if lat_raw else (page.get('lat') if page else None)
        lng = _safe_float(lng_raw) if lng_raw else (page.get('lng') if page else None)

        # --- Redes sociales
        facebook  = request.form['facebook']
        instagram = request.form['instagram']
        tiktok    = request.form['tiktok']

        # --- Operación y servicios
        operating_hours    = request.form['operating_hours']
        services           = request.form['services']
        payment_methods    = request.form['payment_methods']
        delivery_available = 'delivery_available' in request.form

        # --- Plantilla por defecto
        chosen_default_html = request.form.get('default_html') or 'classico'
        if chosen_default_html not in DEFAULT_HTML_TEMPLATES:
            chosen_default_html = 'classico'

        # ====================================================
        #  ARCHIVOS
        # ====================================================
        # carpeta base
        slug_empresa = slugify(page['business_name'] if page else business_name)
        today = datetime.utcnow().strftime('%Y-%m-%d')
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], slug_empresa, today)
        os.makedirs(folder_path, exist_ok=True)

        # 1) Imagen principal (la que ya tenías)
        image = request.files.get('image')
        image_path = page.get('image')
        if image and image.filename != '':
            filename = secure_filename(image.filename)
            ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            final_filename = f"{ts}_{filename}"
            image.save(os.path.join(folder_path, final_filename))
            image_path = f"{slug_empresa}/{today}/{final_filename}"

        # 2) Imagen de portada NUEVA
        cover_image = request.files.get('cover_image')
        cover_image_path = page.get('cover_image')
        if cover_image and cover_image.filename != '':
            filename = secure_filename(cover_image.filename)
            ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            final_filename = f"cover_{ts}_{filename}"
            cover_image.save(os.path.join(folder_path, final_filename))
            cover_image_path = f"{slug_empresa}/{today}/{final_filename}"

        # 3) Galería mixta (imágenes y/o videos SUBIDOS)
        # en el form: <input type="file" name="media_gallery[]" multiple>
        uploaded_medias = request.files.getlist('media_gallery[]')

        # lo que ya había
        existing_gallery = page.get('media_gallery', [])

        # normalizar si antes guardabas así: ["ruta1","ruta2"]
        norm_gallery = []
        if isinstance(existing_gallery, list):
            for item in existing_gallery:
                if isinstance(item, str):
                    # lo consideramos imagen por compatibilidad
                    norm_gallery.append({
                        'type': 'image',
                        'path': item
                    })
                elif isinstance(item, dict) and 'path' in item:
                    norm_gallery.append(item)

        # ahora agregamos lo nuevo
        for f in uploaded_medias:
            if not f or f.filename == '':
                continue
            filename = secure_filename(f.filename)
            ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            final_filename = f"media_{ts}_{filename}"
            save_path = os.path.join(folder_path, final_filename)
            f.save(save_path)

            # detectar tipo por extensión
            ext = os.path.splitext(filename)[1].lower()
            if ext in ['.mp4', '.mov', '.avi', '.mkv', '.webm']:
                media_type = 'video'
            else:
                media_type = 'image'

            norm_gallery.append({
                'type': media_type,
                'path': f"{slug_empresa}/{today}/{final_filename}"
            })

        # ====================================================
        #  ARMAR DATA
        # ====================================================
        new_data = {
            'business_name':  business_name,
            'description':    description,
            'category':       category,
            'slogan':         slogan,
            'founding_date':  founding_date,
            'phone':          phone,
            'whatsapp':       whatsapp,
            'email':          email,
            'website':        website,
            'address':        address,
            'postal_code':    postal_code,
            'city':           city,
            'state':          state,
            'color':          color,
            'lat':            lat,
            'lng':            lng,
            'facebook':       facebook,
            'instagram':      instagram,
            'tiktok':         tiktok,
            'operating_hours': operating_hours,
            'services':        services,
            'payment_methods': payment_methods,
            'delivery_available': delivery_available,
            'image':            image_path,         # la de siempre
            'cover_image':      cover_image_path,   # portada
            'media_gallery':    norm_gallery,       # galería mixta
            'default_html':     chosen_default_html
        }

        # permitir cambiar slug manualmente (opcional)
        posted_slug = (request.form.get('slug') or '').strip()
        if posted_slug:
            normalized = slugify(posted_slug)
            if normalized and normalized != page.get('slug'):
                new_data['slug'] = unique_slug_for_page(normalized)

        mongo.db.page_data.update_one({'_id': page['_id']}, {'$set': new_data})

        final_slug = new_data.get('slug') or page.get('slug')
        flash('Perfil del negocio actualizado exitosamente.')
        return redirect(url_for('manage_page_slug', slug=final_slug))

    selected_default_html = (page or {}).get('default_html', 'classico')
    return render_template(
        'manage_page.html',
        data=page,
        default_html_key=selected_default_html,
        default_html_whitelist=DEFAULT_HTML_TEMPLATES
    )

@app.route('/negocio/<nombre>', methods=['GET', 'POST'])
def detalle_negocio(nombre):
    # trae querystring original (tpl, preview, ts...)
    qs = request.query_string.decode("utf-8")
    suffix = f"?{qs}" if qs else ""

    # 1) Si ya te mandaron un slug, redirige directo
    negocio = mongo.db.page_data.find_one({'slug': nombre})
    if negocio:
        return redirect(url_for('negocio_por_slug', slug=negocio['slug']) + suffix, code=301)

    # 2) Legacy real: business_name (exact match)
    negocio = mongo.db.page_data.find_one({'business_name': nombre})
    if not negocio:
        flash('Negocio no encontrado.')
        return redirect(url_for('index'))

    # 3) Asegura slug y redirige SEO-friendly (CON QS)
    negocio = ensure_page_has_slug(negocio)
    return redirect(url_for('negocio_por_slug', slug=negocio['slug']) + suffix, code=301)

@app.route('/api/leads', methods=['POST'])
def api_create_lead():
    data = request.get_json(silent=True) or {}

    slug = (data.get("slug") or "").strip()
    nombre = (data.get("nombre") or "").strip()
    items = data.get("items") or []
    canal = (data.get("canal") or "whatsapp").strip().lower()

    if not slug or not nombre or not isinstance(items, list) or len(items) == 0:
        return {"ok": False, "error": "payload_invalido"}, 400

    page = mongo.db.page_data.find_one({"slug": slug}, {"_id": 1, "business_name": 1, "whatsapp": 1, "phone": 1})
    if not page:
        return {"ok": False, "error": "negocio_no_encontrado"}, 404

    # normaliza items
    clean_items = []
    for it in items:
        if not isinstance(it, dict):
            continue
        title = (it.get("title") or "").strip()
        qty = int(it.get("qty") or 0)
        if title and qty > 0:
            clean_items.append({"title": title, "qty": qty})

    if not clean_items:
        return {"ok": False, "error": "sin_items"}, 400

    lead = {
        "page_id": page["_id"],
        "slug": slug,
        "customer_name": nombre,
        "items": clean_items,
        "channel": canal,
        "status": "new",
        "created_at": datetime.utcnow(),
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "ua": request.headers.get("User-Agent", "")
    }
    ins = mongo.db.leads.insert_one(lead)

    # evento analytics
    mongo.db.events.insert_one({
        "page_id": page["_id"],
        "slug": slug,
        "type": "lead_created",
        "ts": datetime.utcnow(),
        "meta": {"lead_id": str(ins.inserted_id), "items_count": len(clean_items)}
    })

    return {
        "ok": True,
        "lead_id": str(ins.inserted_id),
        "whatsapp": (page.get("whatsapp") or "").strip(),
        "phone": (page.get("phone") or "").strip()
    }

@app.route('/admin/leads')
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required('admin')
def admin_leads():
    page_id = get_current_page_id()
    leads = list(mongo.db.leads.find({"page_id": page_id}).sort("created_at", -1).limit(200))
    return render_template("admin_leads.html", leads=leads)

@app.route('/api/track', methods=['POST'])
def api_track():
    data = request.get_json(silent=True) or {}
    slug = (data.get("slug") or "").strip()
    etype = (data.get("type") or "").strip()

    if not slug or not etype:
        return {"ok": False}, 400

    page = mongo.db.page_data.find_one({"slug": slug}, {"_id": 1})
    if not page:
        return {"ok": False}, 404

    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    doc = {
        "page_id": page["_id"],
        "slug": slug,
        "type": etype,                 # view, click_whatsapp, click_phone, click_maps...
        "ts": datetime.utcnow(),
        "meta": meta,
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "ua": request.headers.get("User-Agent", "")
    }
    mongo.db.events.insert_one(doc)
    return {"ok": True}


@app.route('/api/appointments', methods=['POST'])
def api_create_appointment():
    data = request.get_json(silent=True) or {}
    slug = (data.get("slug") or "").strip()
    name = (data.get("name") or "").strip()
    phone = (data.get("phone") or "").strip()
    service = (data.get("service") or "").strip()
    start_iso = (data.get("start_at") or "").strip()

    if not slug or not name or not phone or not service or not start_iso:
        return {"ok": False, "error": "faltan_campos"}, 400

    page = mongo.db.page_data.find_one({"slug": slug}, {"_id": 1})
    if not page:
        return {"ok": False, "error": "negocio_no_encontrado"}, 404

    settings = get_page_booking_settings(page["_id"])
    if not settings["enabled"]:
        return {"ok": False, "error": "reservas_deshabilitadas"}, 400

    try:
        start_at = datetime.fromisoformat(start_iso.replace("Z",""))
    except Exception:
        return {"ok": False, "error": "fecha_invalida"}, 400

    # valida día permitido
    if start_at.date().weekday() not in settings["days"]:
        return {"ok": False, "error": "dia_no_disponible"}, 400

    # valida dentro de horario
    open_dt = dt_at(start_at.date(), settings["open"])
    close_dt = dt_at(start_at.date(), settings["close"])
    slot_minutes = settings["slot"]
    end_at = start_at + timedelta(minutes=slot_minutes)

    if not (open_dt <= start_at and end_at <= close_dt):
        return {"ok": False, "error": "fuera_de_horario"}, 400

    # evita choques (pending+approved bloquean)
    conflict = mongo.db.appointments.find_one({
        "page_id": page["_id"],
        "status": {"$in": ["pending", "approved"]},
        "start_at": {"$lt": end_at},
        # end_at puede no existir en legacy; usamos $or
        "$or": [
            {"end_at": {"$gt": start_at}},
            {"end_at": {"$exists": False}}  # legacy: luego filtramos en python
        ]
    }, {"start_at": 1, "end_at": 1, "duration_min": 1})

    if conflict:
        # si es legacy sin end_at, asumimos slot_minutes
        c_start = conflict.get("start_at")
        if conflict.get("end_at"):
            c_end = conflict["end_at"]
        else:
            dur = int(conflict.get("duration_min") or slot_minutes)
            c_end = c_start + timedelta(minutes=dur)

        if c_start and overlaps(start_at, end_at, c_start, c_end):
            return {"ok": False, "error": "slot_ocupado"}, 409

    appt = {
        "page_id": page["_id"],
        "slug": slug,
        "customer_name": name,
        "phone": phone,
        "service_title": service,
        "start_at": start_at,
        "end_at": end_at,
        "duration_min": slot_minutes,
        "status": "pending",
        "created_at": datetime.utcnow()
    }
    ins = mongo.db.appointments.insert_one(appt)

    mongo.db.events.insert_one({
        "page_id": page["_id"],
        "slug": slug,
        "type": "appointment_created",
        "ts": datetime.utcnow(),
        "meta": {"appointment_id": str(ins.inserted_id)}
    })

    return {"ok": True, "appointment_id": str(ins.inserted_id)}

from urllib.parse import quote_plus
from datetime import datetime
from flask import request, redirect, url_for, flash, abort

@app.route('/n/<slug>/reservar', methods=['GET', 'POST'])
def crear_reserva_publica(slug):
    negocio = mongo.db.page_data.find_one({'slug': slug})
    if not negocio:
        abort(404)

    if request.method == 'GET':
        return redirect(url_for('negocio_por_slug', slug=slug) + '#reservas')

    nombre = (request.form.get('nombre') or '').strip()
    telefono = (request.form.get('telefono') or '').strip()
    email = (request.form.get('email') or '').strip()
    servicio = (request.form.get('servicio') or '').strip()
    fecha = (request.form.get('fecha') or '').strip()
    hora = (request.form.get('hora') or '').strip()
    notas = (request.form.get('notas') or '').strip()

    if not nombre or not telefono or not servicio or not fecha or not hora:
        flash('Completa nombre, teléfono, servicio, fecha y hora para reservar.', 'warning')
        return redirect(url_for('negocio_por_slug', slug=slug) + '#reservas')

    cita_dt = None
    try:
        cita_dt = datetime.strptime(f"{fecha} {hora}", "%Y-%m-%d %H:%M")
    except Exception:
        pass

    reserva_doc = {
        'page_id': negocio['_id'],
        'slug': slug,
        'business_name': negocio.get('business_name'),
        'nombre': nombre,
        'telefono': telefono,
        'email': email,
        'servicio': servicio,
        'fecha': fecha,
        'hora': hora,
        'notas': notas,
        'status': 'pendiente',
        'source': 'public_reservation_form',
        'created_at': datetime.utcnow(),
    }

    if cita_dt:
        reserva_doc['appointment_at'] = cita_dt

    mongo.db.reservas.insert_one(reserva_doc)

    flash('Tu reserva fue enviada correctamente. Te contactaremos para confirmar.', 'success')

    wa = (negocio.get('whatsapp') or '').replace(' ', '')
    if wa:
        mensaje = (
            f"Hola, soy {nombre}. "
            f"Quiero reservar una cita en {negocio.get('business_name', 'su negocio')}.\n"
            f"Servicio: {servicio}\n"
            f"Fecha: {fecha}\n"
            f"Hora: {hora}\n"
            f"Teléfono: {telefono}"
        )
        if email:
            mensaje += f"\nEmail: {email}"
        if notas:
            mensaje += f"\nNotas: {notas}"

        return redirect(f"https://wa.me/{wa}?text={quote_plus(mensaje)}")

    return redirect(url_for('negocio_por_slug', slug=slug) + '#reservas')

import calendar as pycal

@app.route("/admin/calendar")
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required("admin")
def admin_calendar():
    page_id = get_current_page_id()

    # mes actual o ?ym=2026-02
    ym = (request.args.get("ym") or "").strip()
    today = datetime.utcnow().date()
    if ym:
        try:
            y, m = [int(x) for x in ym.split("-")]
            year, month = y, m
        except:
            year, month = today.year, today.month
    else:
        year, month = today.year, today.month

    first = date(year, month, 1)
    last_day = pycal.monthrange(year, month)[1]
    last = date(year, month, last_day)

    start_dt = datetime(first.year, first.month, first.day, 0, 0, 0)
    end_dt = datetime(last.year, last.month, last.day, 23, 59, 59)

    appts = list(mongo.db.appointments.find({
        "page_id": page_id,
        "start_at": {"$gte": start_dt, "$lte": end_dt}
    }).sort("start_at", 1))

    # agrupar por YYYY-MM-DD
    by_day = {}
    for a in appts:
        dkey = a["start_at"].strftime("%Y-%m-%d")
        by_day.setdefault(dkey, []).append(a)

    # weeks grid: lista de semanas, cada semana lista de ints (0=empty)
    cal = pycal.Calendar(firstweekday=0)  # 0=Lunes
    weeks = cal.monthdayscalendar(year, month)

    # navegación
    prev_month = (first - timedelta(days=1)).strftime("%Y-%m")
    next_month = (last + timedelta(days=1)).strftime("%Y-%m")

    return render_template(
        "admin_calendar.html",
        year=year,
        month=month,
        ym=f"{year:04d}-{month:02d}",
        weeks=weeks,
        by_day=by_day,
        prev_month=prev_month,
        next_month=next_month
    )

@app.route('/admin/appointments')
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required('admin')
def admin_appointments():
    page_id = get_current_page_id()
    appts = list(mongo.db.appointments.find({"page_id": page_id}).sort("start_at", 1).limit(500))
    return render_template("admin_appointments.html", appts=appts)

@app.route('/admin/appointments/<appt_id>/<action>', methods=['POST'])
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required('admin')
def admin_appointments_action(appt_id, action):
    page_id = get_current_page_id()
    if action not in ["approve", "reject"]:
        return redirect(url_for("admin_appointments"))

    status = "approved" if action == "approve" else "rejected"
    mongo.db.appointments.update_one(
        {"_id": ObjectId(appt_id), "page_id": page_id},
        {"$set": {"status": status, "updated_at": datetime.utcnow()}}
    )
    return redirect(url_for("admin_appointments"))

@app.route('/admin/promos', methods=['GET', 'POST'])
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required('admin')
def admin_promos():
    page_id = get_current_page_id()

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        desc = (request.form.get("description") or "").strip()
        code = (request.form.get("code") or "").strip().upper()
        discount_type = (request.form.get("discount_type") or "percent").strip()
        value = float(request.form.get("value") or 0)
        starts = (request.form.get("starts_at") or "").strip()  # yyyy-mm-dd
        ends = (request.form.get("ends_at") or "").strip()

        if not title:
            flash("Título requerido", "warning")
            return redirect(url_for("admin_promos"))

        def _parse_date(s):
            if not s:
                return None
            try:
                y,m,d = [int(x) for x in s.split("-")]
                return datetime(y,m,d)
            except:
                return None

        doc = {
            "page_id": page_id,
            "title": title,
            "description": desc,
            "code": code or None,
            "discount_type": discount_type,  # percent|fixed|text
            "value": value,
            "starts_at": _parse_date(starts) or datetime.utcnow(),
            "ends_at": _parse_date(ends),
            "active": True,
            "priority": int(request.form.get("priority") or 0),
            "created_at": datetime.utcnow()
        }
        mongo.db.promos.insert_one(doc)
        flash("Promo creada ✅", "success")
        return redirect(url_for("admin_promos"))

    promos = list(mongo.db.promos.find({"page_id": page_id}).sort("created_at", -1))
    return render_template("admin_promos.html", promos=promos)

@app.route('/admin/promos/<promo_id>/toggle', methods=['POST'])
@require_active_subscription
@current_site(required=True)
@login_required
@roles_required('admin')
def admin_promos_toggle(promo_id):
    page_id = get_current_page_id()
    p = mongo.db.promos.find_one({"_id": ObjectId(promo_id), "page_id": page_id})
    if p:
        mongo.db.promos.update_one({"_id": p["_id"]}, {"$set": {"active": not bool(p.get("active", True))}})
    return redirect(url_for("admin_promos"))


from flask import abort
from flask import abort
from jinja2 import TemplateNotFound

@app.route('/n/<slug>', methods=['GET', 'POST'])
def negocio_por_slug(slug):
    negocio = mongo.db.page_data.find_one({'slug': slug})
    if not negocio:
        abort(404)

    negocios = mongo.db.page_data.find()

    posts = list(
        mongo.db.posts.find({'page_id': negocio['_id']})
        .sort('date', -1)
        .limit(3)
    )
    avisos = list(
        mongo.db.avisos.find({'page_id': negocio['_id']})
        .sort('date', -1)
    )
    productos_all = list(mongo.db.productos.find({'page_id': negocio['_id']}))

    productos_fisicos = [p for p in productos_all if p.get('tipo', 'producto') == 'producto']
    servicios = [p for p in productos_all if p.get('tipo', 'producto') == 'servicio']

    reseñas = list(
        mongo.db.reseñas.find({'page_id': negocio['_id']})
        .sort('fecha', -1)
    )

    now = datetime.utcnow()
    promos = list(
        mongo.db.promos.find({
            "page_id": negocio["_id"],
            "active": True,
            "starts_at": {"$lte": now},
            "$or": [
                {"ends_at": None},
                {"ends_at": {"$gte": now}}
            ]
        }).sort([("priority", -1), ("created_at", -1)]).limit(3)
    )

    if request.method == 'POST':
        nombre_usuario = (request.form.get('nombre') or '').strip()
        comentario = (request.form.get('comentario') or '').strip()
        try:
            estrellas = int(request.form.get('estrellas', 0))
        except (TypeError, ValueError):
            estrellas = 0

        if nombre_usuario and comentario and estrellas:
            mongo.db.reseñas.insert_one({
                'page_id': negocio['_id'],
                'nombre': nombre_usuario,
                'comentario': comentario,
                'estrellas': estrellas,
                'fecha': datetime.utcnow()
            })
            flash("Gracias por tu reseña 🙌")
            return redirect(url_for('negocio_por_slug', slug=slug))

    def _to_list(val):
        if isinstance(val, list):
            return [str(x).strip() for x in val if str(x).strip()]
        if isinstance(val, str):
            return [x.strip() for x in val.split(',') if x.strip()]
        return []

    services_list = _to_list(negocio.get('services', ''))
    pm_list = _to_list(negocio.get('payment_methods', ''))

    template_name = get_theme_view(negocio, "site")

    ctx = dict(
        page=negocio,
        negocio=negocio,
        negocios=negocios,
        posts=posts,
        avisos=avisos,
        productos_fisicos=productos_fisicos,
        servicios=servicios,
        reseñas=reseñas,
        services_list=services_list,
        pm_list=pm_list,
        promos=promos,
        slug=slug,
        theme_key=get_theme_key(negocio),
        current_year=datetime.now().year
    )

    try:
        return render_template(template_name, **ctx)
    except TemplateNotFound:
        return render_template(get_theme_view({"default_html": DEFAULT_THEME_KEY}, "site"), **ctx)

@app.route('/negocio/<nombre>/blogs', methods=['GET'])
def lista_blogs_negocio(nombre):
    negocio = mongo.db.page_data.find_one({'business_name': nombre})
    if not negocio:
        flash('Negocio no encontrado.')
        return redirect(url_for('lista_negocios'))

    negocio = ensure_page_has_slug(negocio)
    return redirect(
        url_for(
            'lista_blogs_negocio_slug',
            slug=negocio['slug'],
            **request.args.to_dict()
        )
    )

@app.route('/n/<slug>/blog', methods=['GET'])
def lista_blogs_negocio_slug(slug):
    negocio = mongo.db.page_data.find_one({'slug': slug})
    if not negocio:
        abort(404)

    negocios = mongo.db.page_data.find()

    page = request.args.get('page', 1, type=int)
    per_page = 15
    query = request.args.get('search', '', type=str).strip()

    filtro = {'page_id': negocio['_id']}
    if query:
        filtro['title'] = {'$regex': query, '$options': 'i'}

    posts = list(
        mongo.db.posts.find(filtro)
        .sort('date', -1)
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    total_posts = mongo.db.posts.count_documents(filtro)

    template_name = get_theme_view(negocio, "blog_index")

    ctx = dict(
        page=negocio,
        negocio=negocio,
        negocios=negocios,
        posts=posts,
        total_posts=total_posts,
        page_number=page,
        per_page=per_page,
        query=query,
        slug=slug,
        theme_key=get_theme_key(negocio),
        current_year=datetime.now().year
    )

    try:
        return render_template(template_name, **ctx)
    except TemplateNotFound:
        return render_template(get_theme_view({"default_html": DEFAULT_THEME_KEY}, "blog_index"), **ctx)

@app.route('/n/<slug>/blog/<post_id>', methods=['GET'])
def ver_post_slug(slug, post_id):
    negocio = mongo.db.page_data.find_one({'slug': slug})
    if not negocio:
        abort(404)

    try:
        post = mongo.db.posts.find_one({
            '_id': ObjectId(post_id),
            'page_id': negocio['_id']
        })
    except Exception:
        post = None

    if not post:
        abort(404)

    negocios = mongo.db.page_data.find()

    if isinstance(post.get('date'), datetime):
        post['date'] = post['date'].replace(tzinfo=None)

    related_posts = list(
        mongo.db.posts.find({
            'page_id': negocio['_id'],
            '_id': {'$ne': post['_id']}
        }).sort('date', -1).limit(4)
    )

    template_name = get_theme_view(negocio, "blog_post")

    ctx = dict(
        page=negocio,
        negocio=negocio,
        negocios=negocios,
        post=post,
        related_posts=related_posts,
        slug=slug,
        theme_key=get_theme_key(negocio),
        current_year=datetime.now().year
    )

    try:
        return render_template(template_name, **ctx)
    except TemplateNotFound:
        return render_template(get_theme_view({"default_html": DEFAULT_THEME_KEY}, "blog_post"), **ctx)

@app.route('/negocios')
def lista_negocios():
    negocios = mongo.db.page_data.find() 
    return render_template('lista_negocios.html', negocios=negocios)

@app.route('/post/<post_id>')
def ver_post(post_id):
    try:
        post = mongo.db.posts.find_one({'_id': ObjectId(post_id)})
    except Exception:
        post = None

    if not post:
        return "Post no encontrado", 404

    negocio = mongo.db.page_data.find_one({'_id': post['page_id']}) if post.get('page_id') else None
    if not negocio:
        return "Negocio no encontrado", 404

    negocio = ensure_page_has_slug(negocio)

    return redirect(
        url_for(
            'ver_post_slug',
            slug=negocio['slug'],
            post_id=str(post['_id'])
        )
    )

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user_data = mongo.db.users.find_one({'email': email})

        if user_data:
            # Generar un token seguro
            token = s.dumps(email, salt='password-reset-salt')
            reset_link = url_for('confirm_reset', token=token, _external=True)

            # Mensaje de email
            msg = Message("🔐 Restablece tu contraseña", recipients=[email])
            msg.body = f"""Hola {user_data.get('name', '')},

Recibimos una solicitud para restablecer tu contraseña. 
Para continuar, haz clic en el siguiente enlace:

{reset_link}

Si no solicitaste esto, ignora este correo.

Gracias,
Equipo de soporte
"""
            # HTML opcional (si tu cliente lo soporta)
            msg.html = render_template_string("""
                <p>Hola {{ name }},</p>
                <p>Recibimos una solicitud para <strong>restablecer tu contraseña</strong>.</p>
                <p>Haz clic en el siguiente botón para continuar:</p>
                <p style="text-align: center;">
                    <a href="{{ reset_link }}" style="padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">
                        Restablecer contraseña
                    </a>
                </p>
                <p>Si no solicitaste esto, puedes ignorar este correo.</p>
                <p>Gracias,<br>Equipo de soporte</p>
            """, name=user_data.get('name', 'Usuario'), reset_link=reset_link)

            try:
                mail.send(msg)
                flash("📧 Te enviamos un enlace para restablecer tu contraseña. Revisa tu correo.", 'success')
                return redirect(url_for('login'))
            except Exception as e:
                print(e)  # para debugging en consola
                flash("❌ Error al enviar el correo. Intenta de nuevo más tarde.", 'danger')
                return redirect(url_for('reset_password'))
        else:
            flash("⚠️ No se encontró una cuenta con ese correo electrónico.", 'danger')

    return render_template('reset_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def confirm_reset(token):
    try:
        # Verificar el token
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hora de validez
    except:
        flash("El enlace de restablecimiento de contraseña ha caducado o no es válido.", 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password)

        # Actualizar la contraseña del usuario
        mongo.db.users.update_one({'email': email}, {'$set': {'password': hashed_password}})
        flash('Tu contraseña ha sido restablecida con éxito.', 'success')
        return redirect(url_for('login'))

    return render_template('confirm_reset_password.html', token=token)

@app.route('/robots.txt')
def robots():
    return app.send_static_file('robots.txt')

def get_all_posts():
    posts = mongo.db.blog_posts.find({}, {'updated_at': 1})
    return list(posts)

def get_all_business_pages():
    negocios = mongo.db.page_data.find({}, {'business_name': 1, 'slug': 1})
    return list(negocios)


@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
    pages = []

    # Página principal
    pages.append({
        'loc': url_for('index', _external=True),
        'lastmod': datetime.utcnow().date().isoformat()
    })

    # Obtener negocios
    negocios = get_all_business_pages()
    print(f"[DEBUG] Negocios encontrados: {len(negocios)}")

    for page in negocios:
        # Usar slug si existe, si no usar business_name
        slug = page.get('slug') or page.get('business_name')

        if slug:
            # Normalizar el slug (minúsculas, espacios -> guiones)
            slug = slug.strip().lower().replace(" ", "-")
            print(f"[DEBUG] Slug generado: {slug}")

            try:
                pages.append({
                    'loc': url_for('detalle_negocio', nombre=slug, _external=True),
                    'lastmod': datetime.utcnow().date().isoformat()
                })
            except Exception as e:
                print(f"[ERROR] No se pudo construir URL para negocio con slug '{slug}': {e}")

    # Generar XML
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'

    for page in pages:
        xml += '  <url>\n'
        xml += f'    <loc>{page["loc"]}</loc>\n'
        xml += f'    <lastmod>{page["lastmod"]}</lastmod>\n'
        xml += '    <changefreq>weekly</changefreq>\n'
        xml += '    <priority>0.8</priority>\n'
        xml += '  </url>\n'

    xml += '</urlset>'

    return Response(xml, mimetype='application/xml')

@app.route('/admin/reseñas')
@require_active_subscription
@login_required
def admin_reseñas():
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.')
        return redirect(url_for('sites'))
    reseñas = list(mongo.db.reseñas.find({'page_id': page_id}).sort('fecha', -1))
    return render_template('admin_reseñas.html', reseñas=reseñas)

@app.route('/admin/reviews/delete/<review_id>', methods=['POST'])
@require_active_subscription
@login_required
def delete_review(review_id):
    try:
        review = mongo.db.reseñas.find_one({'_id': ObjectId(review_id)})
        user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})

        if review and user and review['page_id'] == user['page_id']:
            mongo.db.reseñas.delete_one({'_id': ObjectId(review_id)})
            flash('Reseña eliminada exitosamente.')
        else:
            flash('No autorizado para eliminar esta reseña.')

    except Exception as e:
        flash(f'Error al eliminar reseña: {e}')

    return redirect(url_for('admin_reseñas'))

@app.context_processor
def inject_recaptcha_key():
    return dict(RECAPTCHA_SITE_KEY=os.getenv("RECAPTCHA_SITE_KEY"))

@app.route("/api/availability", methods=["GET"])
def api_availability():
    slug = (request.args.get("slug") or "").strip()
    dstr = (request.args.get("date") or "").strip()  # YYYY-MM-DD

    if not slug or not dstr:
        return {"ok": False, "error": "faltan_parametros"}, 400

    page = mongo.db.page_data.find_one({"slug": slug}, {"_id": 1, "timezone": 1})
    if not page:
        return {"ok": False, "error": "negocio_no_encontrado"}, 404

    try:
        day = parse_date_ymd(dstr)
    except Exception:
        return {"ok": False, "error": "fecha_invalida"}, 400

    rules = get_booking_rules(page["_id"])
    if not rules["enabled"]:
        return {"ok": True, "date": dstr, "slots": []}

    # 1) Excepción del día (festivo/cerrado/horario especial)
    ex = get_exception_for_day(page["_id"], day)
    if ex and ex.get("type") == "closed":
        return {"ok": True, "date": dstr, "slots": [], "closed": True, "reason": ex.get("reason")}

    # 2) Regla semanal del día
    # weekday(): 0=Lun ... 6=Dom
    wkey = str(day.weekday())
    dcfg = (rules["weekly"].get(wkey) or {})

    # si no hay excepción y el día está cerrado en weekly => no slots
    if (not ex) and bool(dcfg.get("closed")):
        return {"ok": True, "date": dstr, "slots": [], "closed": True}

    # resolver open/close/breaks finales
    if ex and ex.get("type") == "custom_hours":
        open_h = (ex.get("open") or "").strip()
        close_h = (ex.get("close") or "").strip()
        breaks = ex.get("breaks") if isinstance(ex.get("breaks"), list) else []
    else:
        open_h = (dcfg.get("open") or "").strip()
        close_h = (dcfg.get("close") or "").strip()
        breaks = dcfg.get("breaks") if isinstance(dcfg.get("breaks"), list) else []

    if not open_h or not close_h:
        return {"ok": True, "date": dstr, "slots": []}

    slot_minutes = int(rules["slot"])
    start_day = dt_at(day, open_h)
    end_day = dt_at(day, close_h)

    break_ranges = dt_range_from_breaks(day, breaks)

    # citas del día (ocupan si pending/approved)
    day_start = datetime(day.year, day.month, day.day, 0, 0, 0)
    day_end = day_start + timedelta(days=1)

    appts = list(mongo.db.appointments.find({
        "page_id": page["_id"],
        "start_at": {"$gte": day_start, "$lt": day_end},
        "status": {"$in": ["pending", "approved"]}
    }, {"start_at": 1, "end_at": 1, "duration_min": 1}))

    slots = []
    cur = start_day
    while cur + timedelta(minutes=slot_minutes) <= end_day:
        slot_end = cur + timedelta(minutes=slot_minutes)

        # breaks
        if is_in_breaks(cur, slot_end, break_ranges):
            cur += timedelta(minutes=slot_minutes)
            continue

        # ocupado por cita
        busy = False
        for a in appts:
            a_start = a.get("start_at")
            a_end = a.get("end_at")
            if not a_end:
                dur = int(a.get("duration_min") or slot_minutes)
                a_end = a_start + timedelta(minutes=dur)

            if a_start and overlaps(cur, slot_end, a_start, a_end):
                busy = True
                break

        if not busy:
            slots.append(cur.isoformat())

        cur += timedelta(minutes=slot_minutes)

    return {
        "ok": True,
        "date": dstr,
        "slot_minutes": slot_minutes,
        "slots": slots,
        "exception": bool(ex)
    }

@app.route('/enviar', methods=['POST'])
def enviar():
    nombre = request.form.get('nombre')
    correo = request.form.get('correo')
    mensaje = request.form.get('mensaje')
    captcha_response = request.form.get('g-recaptcha-response')

    if not nombre or not correo or not mensaje:
        flash('Por favor completa todos los campos.', 'error')
        return redirect(request.referrer or url_for('index'))

    # Validar reCAPTCHA
    if not captcha_response:
        flash('Por favor verifica que no eres un robot.', 'danger')
        return redirect(request.referrer or url_for('index'))

    verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {'secret': RECAPTCHA_SECRET_KEY, 'response': captcha_response}
    r = requests.post(verify_url, data=payload)
    result = r.json()

    if not result.get('success'):
        flash('Verificación de reCAPTCHA fallida. Intenta de nuevo.', 'danger')
        return redirect(request.referrer or url_for('index'))

    # Guardar en la colección "mensajes"
    mongo.db.mensajes.insert_one({
        'nombre': nombre,
        'correo': correo,
        'mensaje': mensaje
    })

    # Enviar correo
    try:
        msg = Message(
            subject=f"📩 Nuevo mensaje de contacto - {nombre}",
            recipients=["technologydavani@gmail.com"]
        )
        msg.body = f"""
        Has recibido un nuevo mensaje desde el sitio web:

        Nombre: {nombre}
        Correo: {correo}

        Mensaje:
        {mensaje}
        """
        msg.html = render_template_string("""
        <h3>📩 Nuevo mensaje de contacto</h3>
        <p><strong>Nombre:</strong> {{ nombre }}</p>
        <p><strong>Correo:</strong> {{ correo }}</p>
        <p><strong>Mensaje:</strong></p>
        <div style="background-color: #f7f7f7; padding: 10px; border-left: 3px solid #007BFF;">
          {{ mensaje }}
        </div>
        """, nombre=nombre, correo=correo, mensaje=mensaje)

        mail.send(msg)
        flash('¡Mensaje enviado correctamente!', 'success')
        return redirect(url_for('gracias'))

    except Exception as e:
        print(f"Error al enviar correo: {e}")
        flash('Hubo un problema al enviar tu mensaje. Intenta de nuevo más tarde.', 'danger')
        return redirect(request.referrer or url_for('index'))

@app.route('/gracias')
def gracias():
    return render_template('gracias.html')

@app.route('/ads.txt')
def ads():
    return send_from_directory(os.path.abspath(os.path.dirname(__file__)), 'ads.txt')

if __name__ == '__main__':
  app.run(host="0.0.0.0", port=5000, debug=True)