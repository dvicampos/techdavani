from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory, render_template_string, Response
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from datetime import datetime
from bson.objectid import ObjectId
from functools import wraps
import os
import re
from dotenv import load_dotenv
import requests
from jinja2 import TemplateNotFound
from urllib.parse import urlparse
from datetime import datetime, date, timedelta

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
        flash("Error al obtener usuario.")
        return redirect(url_for('login'))

    if not user:
        flash("Usuario no encontrado.")
        return redirect(url_for('login'))

    page_id = user.get('page_id')
    posts = mongo.db.posts.find({'page_id': page_id})
    
    return render_template('list_post.html', posts=posts)

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
        'resenas':   mongo.db.resenas.count_documents({'page_id': page_id}) if 'resenas' in mongo.db.list_collection_names() else 0,
        'usuarios':  mongo.db.users.count_documents({}) if current_user.role == 'admin' else 0,
    }

    # --- Recientes (top 6 por fecha) ---
    recientes = {
        'posts':     list(mongo.db.posts.find({'page_id': page_id}).sort('created_at', -1).limit(6)),
        'avisos':    list(mongo.db.avisos.find({'page_id': page_id}).sort('created_at', -1).limit(6)),
        'productos': list(mongo.db.productos.find({'page_id': page_id}).sort('created_at', -1).limit(6)),
    }

    return render_template('dashboard.html', page=page, stats=stats, recientes=recientes)

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

# productos
@app.route('/productos')
@require_active_subscription
@login_required
def list_productos():
    page_id = get_current_page_id()
    if not page_id:
        flash('Selecciona un sitio.')
        return redirect(url_for('sites'))

    productos = list(mongo.db.productos.find({'page_id': page_id}))
    return render_template('list_productos.html', productos=productos)

from werkzeug.utils import secure_filename
import os

@app.route('/create_producto', methods=['GET', 'POST'])
@require_active_subscription
@login_required
def create_producto():
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    if not user:
        flash('Usuario no encontrado.')
        return redirect(url_for('logout'))

    page_id = user.get('page_id')

    if request.method == 'POST':
        title        = request.form['title']
        description  = request.form['description']
        price        = float(request.form['price'])
        show_price   = 'show_price' in request.form

        tipo         = request.form.get('tipo', 'producto').strip().lower()  

        image_file = request.files['image']
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
            'price': price,
            'image': image_path,
            'page_id': page_id,
            'show_price': show_price,

            'tipo': tipo
        })

        flash('Elemento creado correctamente.')
        return redirect(url_for('list_productos'))

    tipos_posibles = ['producto', 'servicio']
    return render_template('create_producto.html', tipos_posibles=tipos_posibles)

@app.route('/edit_producto/<producto_id>', methods=['GET', 'POST'])
@require_active_subscription
@login_required
def edit_producto(producto_id):
    producto = mongo.db.productos.find_one({'_id': ObjectId(producto_id)})

    if not producto:
        flash('Producto no encontrado.')
        return redirect(url_for('list_productos'))

    if request.method == 'POST':
        title        = request.form['title']
        description  = request.form['description']
        price        = float(request.form['price'])
        show_price   = 'show_price' in request.form

        tipo         = request.form.get('tipo', 'producto').strip().lower()

        image_file = request.files.get('image')
        image_path = producto.get('image')

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

        mongo.db.productos.update_one(
            {'_id': ObjectId(producto_id)},
            {'$set': {
                'title': title,
                'description': description,
                'price': price,
                'image': image_path,
                'show_price': show_price,

                'tipo': tipo
            }}
        )

        flash('Elemento actualizado correctamente.')
        return redirect(url_for('list_productos'))

    tipos_posibles = ['producto', 'servicio']
    return render_template('edit_producto.html', producto=producto, tipos_posibles=tipos_posibles)

@app.route('/delete_producto/<producto_id>', methods=['POST'])
@require_active_subscription
@login_required
def delete_producto(producto_id):
    producto = mongo.db.productos.find_one({'_id': ObjectId(producto_id)})
    
    if not producto:
        flash('Producto no encontrado.')
        return redirect(url_for('list_productos'))

    mongo.db.productos.delete_one({'_id': ObjectId(producto_id)})
    flash('Producto eliminado correctamente.')
    return redirect(url_for('list_productos'))


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
    "base": "detalle_negocio.html",
    "classico": "public/page_core.html",
    "brutal":  "public/page_public_crafts.html",
    "restaurante": "public/restaurant.html",
    "barber": "public/barber.html",
    "rope": "public/rope.html",
    "coffe": "public/coffe.html",
    "dentist": "public/dentist.html",
    "flowers": "public/floreria.html",
    "restaurantblack": "public/restaurant_min.html",
    "festivo": "public/festivo.html",
    "salon_belleza": "public/barber_1.html",
    "dentista": "public/dentista.html",
    "inflables": "public/inflables.html",
    "alquiler": "public/alquiler.html",
    "cafe_celebrate": "public/cafe_celebrate.html",
    "bar_restaurant": "public/bar_restaurant.html",
    "bar_rockandroll": "public/bar_rockandroll.html",
    "videojuegos_sala": "public/videojuegos_sala.html",
    "musica": "public/musica.html",
    "belleza_premium": "public/belleza_premium.html",
    "tienda_regalos": "public/tienda_regalos.html",
    "bisuteria": "public/bisuteria.html",
}

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
    negocio = mongo.db.page_data.find_one({'business_name': nombre})
    negocios = mongo.db.page_data.find()  # si lo usas en sidebars, etc.

    if not negocio:
        flash('Negocio no encontrado.')
        return redirect(url_for('index'))

    # Colecciones asociadas
    posts     = list(mongo.db.posts.find({'page_id': negocio['_id']}).limit(3))
    avisos    = list(mongo.db.avisos.find({'page_id': negocio['_id']}))
    productos_all = list(mongo.db.productos.find({'page_id': negocio['_id']}))

    productos_fisicos = [p for p in productos_all if p.get('tipo', 'producto') == 'producto']
    servicios        = [p for p in productos_all if p.get('tipo', 'producto') == 'servicio']

    reseñas   = list(mongo.db.reseñas.find({'page_id': negocio['_id']}))


    # Alta de reseña (POST)
    if request.method == 'POST':
        nombre_usuario = request.form.get('nombre')
        comentario     = request.form.get('comentario')
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
            return redirect(url_for('detalle_negocio', nombre=nombre))

    # ---- Normalizar a listas para evitar usar filtros no disponibles en Jinja ----
    def _to_list(val):
        """Acepta list o string con comas y devuelve lista limpia de strings."""
        if isinstance(val, list):
            return [str(x).strip() for x in val if str(x).strip()]
        if isinstance(val, str):
            return [x.strip() for x in val.split(',') if x.strip()]
        return []

    services_list = _to_list(negocio.get('services', ''))
    pm_list       = _to_list(negocio.get('payment_methods', ''))

    # ===== Elegir plantilla por default_html o override via ?tpl= =====
    tpl_key = request.args.get('tpl') or negocio.get('default_html') or 'classico'
    template_name = DEFAULT_HTML_TEMPLATES.get(tpl_key, DEFAULT_HTML_TEMPLATES['classico'])

    ctx = dict(
        page=negocio,
        negocios=negocios,
        posts=posts,
        avisos=avisos,
        productos_fisicos=productos_fisicos,
        servicios=servicios,
        reseñas=reseñas,
        services_list=services_list,   # <-- para chips
        pm_list=pm_list                # <-- para chips
    )

    try:
        return render_template(template_name, **ctx)
    except TemplateNotFound:
        # Fallback duro
        return render_template(DEFAULT_HTML_TEMPLATES['classico'], **ctx)

@app.route('/negocios')
def lista_negocios():
    negocios = mongo.db.page_data.find() 
    return render_template('lista_negocios.html', negocios=negocios)

@app.route('/post/<post_id>')
def ver_post(post_id):
    negocios = mongo.db.page_data.find()
    post = mongo.db.posts.find_one({'_id': ObjectId(post_id)})
    if not post:
        return "Post no encontrado", 404

    post['date'] = post['date'].replace(tzinfo=None) if isinstance(post['date'], datetime) else datetime.utcnow()
    negocio = mongo.db.page_data.find_one({'_id': post['page_id']}) if 'page_id' in post else None

    return render_template(
        'post_detalle.html',
        post=post,
        negocio=negocio,
        negocios=negocios,
        current_year=datetime.now().year
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


@app.route('/negocio/<nombre>/blogs', methods=['GET', 'POST'])
def lista_blogs_negocio(nombre):
    # Buscar el negocio por nombre
    negocio = mongo.db.page_data.find_one({'business_name': nombre})
    negocios = mongo.db.page_data.find()
    if not negocio:
        flash('Negocio no encontrado.')
        return redirect(url_for('lista_negocios'))  # Redirige si no se encuentra el negocio

    # Paginación
    page = request.args.get('page', 1, type=int)  # Página actual
    per_page = 15  # Número de posts por página

    # Obtener la búsqueda (si existe)
    query = request.args.get('search', '', type=str)

    # Si hay búsqueda, buscar posts que coincidan con el término
    if query:
        posts = list(
            mongo.db.posts.find({
                'page_id': negocio['_id'],
                'title': {'$regex': query, '$options': 'i'}
            }).skip((page - 1) * per_page).limit(per_page)
        )
    else:
        posts = list(
            mongo.db.posts.find({'page_id': negocio['_id']})
            .skip((page - 1) * per_page).limit(per_page)
        )

    total_posts = mongo.db.posts.count_documents({'page_id': negocio['_id']})

    return render_template(
        'lista_blogs_negocio.html',
        negocio=negocio,
        negocios=negocios,
        posts=posts,
        total_posts=total_posts,
        page=page,
        per_page=per_page,
        query=query
    )


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