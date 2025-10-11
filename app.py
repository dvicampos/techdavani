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

class User(UserMixin):
    def __init__(self, user_data):
        self._id = str(user_data['_id'])  # almacena el _id como string
        self.email = user_data['email']
        self.nombre = user_data['nombre']
        self.password = user_data['password']
        self.role = user_data.get('role')
        self.page_id = user_data.get('page_id')

    @property
    def id(self):
        return self._id
     

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


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


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
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        page_id = request.form['page_id']

        user = mongo.db.users.find_one({'email': email})
        if user:
            flash('Este correo ya existe')
            return redirect(url_for('register', page_id=page_id))

        mongo.db.users.insert_one({
            'nombre': nombre,
            'email': email,
            'password': password,
            'confirmed': False,
            'role': role,
            'page_id': ObjectId(page_id)
        })

        # Enviar email de confirmación (como ya lo haces)
        token = s.dumps(email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('confirm_email.html', confirm_url=confirm_url)

        msg = Message('Confirma tu correo', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.html = html
        mail.send(msg)

        flash('Revisa tu correo para confirmar tu cuenta')
        return redirect(url_for('manage_users'))

    # Solo mostrar el formulario si hay un page_id
    page_id = request.args.get('page_id')
    if not page_id:
        flash('No se puede registrar un usuario sin una empresa asociada')
        return redirect(url_for('create_page'))

    return render_template('register.html', page_id=page_id)


@app.route('/admin/register_user', methods=['GET', 'POST'])
@login_required
def admin_register_user():
    # Validar que el usuario actual sea admin
    if current_user.role != 'admin':
        flash('No tienes permiso para acceder a esta página.')
        return redirect(url_for('index'))

    # Obtener el page_id del usuario logueado (admin)
    page_id = current_user.page_id  # Aquí depende cómo tengas guardado el page_id en current_user

    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']

        # Verificar si el usuario ya existe
        user = mongo.db.users.find_one({'email': email})
        if user:
            flash('Este correo ya existe')
            return redirect(url_for('admin_register_user'))

        # Insertar nuevo usuario asociado a la misma empresa (page_id)
        mongo.db.users.insert_one({
            'nombre': nombre,
            'email': email,
            'password': password,
            'confirmed': False,
            'role': role,
            'page_id': ObjectId(page_id)
        })

        # Enviar email de confirmación
        token = s.dumps(email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('confirm_email.html', confirm_url=confirm_url)

        msg = Message('Confirma tu correo', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.html = html
        mail.send(msg)

        flash('Usuario registrado. Revisa el correo para confirmar la cuenta.')
        return redirect(url_for('manage_users'))

    # En GET, mostrar el formulario, sin page_id porque ya lo sabemos
    return render_template('admin_register_user.html', page_id=page_id)

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
        email = request.form['email']
        password = request.form['password']
        
        user_data = mongo.db.users.find_one({'email': email})

        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)  # aquí pasamos el diccionario completo
            login_user(user)
            flash('Inicio de sesión exitoso.')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales inválidas.')
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
@require_lifetime
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
@require_lifetime
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
@require_lifetime
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
@require_lifetime
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
@require_lifetime
@login_required
def posts():
    posts = list(mongo.db.posts.find().sort('date', -1))
    return render_template('posts.html', posts=posts)

@app.route('/dashboard')
@require_lifetime
@login_required
def dashboard():
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    page = mongo.db.pages.find_one({'_id': user.get('page_id')})
    return render_template('dashboard.html', page=page)

# AVISOS
@app.route('/avisos')
@require_lifetime
@login_required
def list_avisos():
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    if not user:
        flash('Usuario no encontrado.')
        return redirect(url_for('logout'))  # o a alguna ruta segura

    page_id = user.get('page_id')
    avisos = list(
        mongo.db.avisos.find({'page_id': page_id}).sort('date', -1)
    )
    return render_template('list_avisos.html', avisos=avisos)

# Ruta para crear un nuevo aviso
@app.route('/create_aviso', methods=['GET', 'POST'])
@require_lifetime
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
@require_lifetime
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
@require_lifetime
@login_required
def delete_aviso(aviso_id):
    aviso = mongo.db.avisos.find_one({'_id': ObjectId(aviso_id)})
    if aviso and aviso['author'] == current_user.id:
        mongo.db.avisos.delete_one({'_id': ObjectId(aviso_id)})
        flash('Aviso eliminado correctamente.')
    return redirect(url_for('list_avisos'))

# productos
@app.route('/productos')
@require_lifetime
@login_required
def list_productos():
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    if not user:
        flash('Usuario no encontrado.')
        return redirect(url_for('logout'))

    page_id = user.get('page_id')
    productos = list(mongo.db.productos.find({'page_id': page_id}))
    return render_template('list_productos.html', productos=productos)

from werkzeug.utils import secure_filename
import os

@app.route('/create_producto', methods=['GET', 'POST'])
@require_lifetime
@login_required
def create_producto():
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    if not user:
        flash('Usuario no encontrado.')
        return redirect(url_for('logout'))

    page_id = user.get('page_id')

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])
        show_price = 'show_price' in request.form

        # Manejo de imagen
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

            # Guardar ruta relativa
            image_path = f"{slug}/{today}/{final_filename}"

        mongo.db.productos.insert_one({
            'title': title,
            'description': description,
            'price': price,
            'image': image_path,
            'page_id': page_id,
            'show_price': show_price
        })

        flash('Producto creado correctamente.')
        return redirect(url_for('list_productos'))

    return render_template('create_producto.html')

@app.route('/edit_producto/<producto_id>', methods=['GET', 'POST'])
@require_lifetime
@login_required
def edit_producto(producto_id):
    producto = mongo.db.productos.find_one({'_id': ObjectId(producto_id)})

    if not producto:
        flash('Producto no encontrado.')
        return redirect(url_for('list_productos'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])
        show_price = 'show_price' in request.form

        # Imagen nueva (si se carga)
        image_file = request.files.get('image')
        image_path = producto.get('image')  # mantener la anterior si no hay nueva

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
                'show_price': show_price
            }}
        )

        flash('Producto actualizado correctamente.')
        return redirect(url_for('list_productos'))

    return render_template('edit_producto.html', producto=producto)

@app.route('/delete_producto/<producto_id>', methods=['POST'])
@require_lifetime
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
@require_lifetime
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
@require_lifetime
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
    return {
        "Authorization": f"Bearer {os.getenv('MP_ACCESS_TOKEN')}",
        "Content-Type": "application/json"
    }

@app.route('/pay/lifetime')
@login_required
def pay_lifetime():
    page_id = request.args.get('page_id')
    if not page_id:
        flash('Falta page_id')
        return redirect(url_for('create_page'))

    if page_has_purchase(page_id, "lifetime"):
        flash('Licencia ya activa. 🎉')
        return redirect(url_for('dashboard'))

    # Leer cupón desde la URL (?coupon=LANZAMIENTO) – la vista ya lo manda cuando corresponde
    coupon_param = request.args.get('coupon', '').strip() or None

    # Resolver precio final y cupon aplicado (si procede)
    unit_price, applied_coupon = resolve_lifetime_price_for_checkout(coupon_param)

    success_url = os.getenv("MP_SUCCESS_URL")
    failure_url = os.getenv("MP_FAILURE_URL")
    webhook_url = os.getenv("MP_WEBHOOK_URL")

    # (Opcional) etiqueta el cupón en el título del ítem para identificarlo en MP
    item_title = "Licencia de por vida"
    if applied_coupon:
        item_title += f" (cupón: {applied_coupon['code']})"

    payload = {
        "items": [{
            "title": item_title,
            "quantity": 1,
            "currency_id": "MXN",
            "unit_price": float(f"{unit_price:.2f}")  # asegúrate que va con 2 decimales
        }],
        "auto_return": "approved",
        "back_urls": {
            "success": success_url,
            "failure": failure_url,
            "pending": success_url
        },
        "notification_url": webhook_url,
        # Mantén tu reference igual para no romper el webhook:
        "external_reference": f"{current_user.id}|{page_id}|lifetime"
    }

    # Si quieres dejar rastro "formal" del cupón en la preferencia (no siempre lo expone MP en el webhook),
    # puedes usar "metadata" (si tu cuenta/SDK lo soporta):
    if applied_coupon:
        payload["metadata"] = {
            "coupon_code": applied_coupon["code"],
            "coupon_type": applied_coupon["type"],
            "coupon_value": applied_coupon["value"],
            "discount_amount": applied_coupon["discount_amount"]
        }

    try:
        r = requests.post(MP_PREFS_URL, headers=mp_headers(), data=json.dumps(payload))
        pref = r.json()
        init_point = pref.get("init_point") or pref.get("sandbox_init_point")
        if not init_point:
            print("MP preference response:", pref)
            flash('No se pudo iniciar el pago.')
            return redirect(url_for('dashboard'))
        return redirect(init_point)
    except Exception as e:
        print("MP error:", e)
        flash('Error creando la preferencia de pago.')
        return redirect(url_for('dashboard'))
  
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

        # Si aprobado, activamos
        if status == 'approved' and addon_slug == 'lifetime' and page_id:
            set_page_license_lifetime(page_id)

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

app.config['UPLOAD_FOLDER'] = '/uploads'
@app.route('/create_page', methods=['GET', 'POST'])
def create_page():
    if request.method == 'POST':
        business_name = request.form['business_name']
        description = request.form['description']
        category = request.form['category']
        slogan = request.form['slogan']
        founding_date = request.form['founding_date']

        # Contacto y ubicación
        phone = request.form['phone']
        whatsapp = request.form['whatsapp']
        email_contact = request.form['email']
        website = request.form['website']
        address = request.form['address']
        postal_code = request.form['postal_code']
        city = request.form['city']
        state = request.form['state']
        color = request.form['color']

        # ⚠️ NUEVO: leer coordenadas del formulario (hidden inputs)
        lat = request.form.get('lat')
        lng = request.form.get('lng')

        # Redes sociales
        facebook = request.form['facebook']
        instagram = request.form['instagram']
        tiktok = request.form['tiktok']

        # Operación y servicios
        operating_hours = request.form['operating_hours']
        services = request.form['services']
        payment_methods = request.form['payment_methods']
        delivery_available = request.form.get('delivery_available') == 'on'

        # Imagen (opcional)
        image = request.files['image']
        image_path = None

        if image and image.filename != '':
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
            except:
                return None

        new_page = {
            'business_name': business_name,
            'description': description,
            'category': category,
            'slogan': slogan,
            'founding_date': founding_date,
            'phone': phone,
            'whatsapp': whatsapp,
            'email': email_contact,
            'website': website,
            'address': address,
            'postal_code': postal_code,
            'city': city,
            'state': state,
            'color': color,
            'lat': _safe_float(lat),
            'lng': _safe_float(lng),
            'facebook': facebook,
            'instagram': instagram,
            'tiktok': tiktok,
            'operating_hours': operating_hours,
            'services': services,
            'payment_methods': payment_methods,
            'delivery_available': delivery_available,
            'image': image_path
        }

        result = mongo.db.page_data.insert_one(new_page)
        page_id = result.inserted_id
        flash('Empresa creada exitosamente. Ahora registra el usuario administrador.')
        return redirect(url_for('register', page_id=str(page_id)))

    return render_template('create_page.html')

@app.route('/manage_page', methods=['GET', 'POST'])
@require_lifetime
@login_required
@roles_required('admin')
def manage_page():
    # (roles_required ya valida admin, este if extra es opcional)
    if current_user.role != 'admin':
        flash('Acceso denegado.')
        return redirect(url_for('dashboard'))

    user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    if not user:
        flash('Usuario no encontrado.')
        return redirect(url_for('login'))

    page_id = user.get('page_id')
    if not page_id:
        flash('No tienes una página asignada')
        return redirect(url_for('dashboard'))

    # page_id suele ser ObjectId; si lo tuvieras como string, usa ObjectId(page_id)
    data = mongo.db.page_data.find_one({'_id': page_id})

    if request.method == 'POST':
        # --- Información básica
        business_name = request.form['business_name']
        description   = request.form['description']
        category      = request.form['category']
        slogan        = request.form['slogan']
        founding_date = request.form['founding_date']

        # --- Contacto y ubicación
        phone        = request.form['phone']
        whatsapp     = request.form['whatsapp']
        email        = request.form['email']
        website      = request.form['website']
        address      = request.form.get('address')
        postal_code  = request.form['postal_code']
        city         = request.form['city']
        state        = request.form['state']
        color        = request.form['color']
        lat_raw      = request.form.get('lat')
        lng_raw      = request.form.get('lng')

        def _safe_float(v):
            try:
                return float(v)
            except:
                return None

        lat = _safe_float(lat_raw) if lat_raw else (data.get('lat') if data else None)
        lng = _safe_float(lng_raw) if lng_raw else (data.get('lng') if data else None)

        # --- Redes sociales
        facebook = request.form['facebook']
        instagram = request.form['instagram']
        tiktok = request.form['tiktok']

        # --- Operación y servicios
        operating_hours  = request.form['operating_hours']
        services         = request.form['services']
        payment_methods  = request.form['payment_methods']
        delivery_available = 'delivery_available' in request.form

        # --- Imagen (opcional)
        image = request.files.get('image')
        image_path = data['image'] if data and 'image' in data else None

        if image and image.filename != '':
            slug_empresa = slugify(data['business_name'] if data else business_name)
            today = datetime.utcnow().strftime('%Y-%m-%d')
            folder_path = os.path.join(app.config['UPLOAD_FOLDER'], slug_empresa, today)
            os.makedirs(folder_path, exist_ok=True)

            filename = secure_filename(image.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            final_filename = f"{timestamp}_{filename}"
            full_path = os.path.join(folder_path, final_filename)
            image.save(full_path)

            image_path = f"{slug_empresa}/{today}/{final_filename}"

        # --- Armar payload (sin google_maps y sin keys duplicadas)
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
            'image':            image_path
        }

        if data:
            mongo.db.page_data.update_one({'_id': page_id}, {'$set': new_data})
        else:
            # si no existía, asegúrate de guardar _id=page_id si es tu modelo
            new_data['_id'] = page_id
            mongo.db.page_data.insert_one(new_data)

        flash('Perfil del negocio actualizado exitosamente.')
        return redirect(url_for('dashboard'))

    return render_template('manage_page.html', data=data)

@app.route('/negocio/<nombre>', methods=['GET', 'POST'])
def detalle_negocio(nombre):
    negocio = mongo.db.page_data.find_one({'business_name': nombre})
    negocios = mongo.db.page_data.find()

    if not negocio:
        flash('Negocio no encontrado.')
        return redirect(url_for('index'))

    posts = list(mongo.db.posts.find({'page_id': negocio['_id']}).limit(3))
    avisos = list(mongo.db.avisos.find({'page_id': negocio['_id']}))
    productos = list(mongo.db.productos.find({'page_id': negocio['_id']}))
    reseñas = list(mongo.db.reseñas.find({'page_id': negocio['_id']}))

    if request.method == 'POST':
        nombre_usuario = request.form.get('nombre')
        comentario = request.form.get('comentario')
        estrellas = int(request.form.get('estrellas', 0))

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

    return render_template(
        'detalle_negocio.html',
        page=negocio,
        negocios=negocios,
        posts=posts,
        avisos=avisos,
        productos=productos,
        reseñas=reseñas
    )



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
@require_lifetime
@login_required
def admin_reseñas():
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    if not user:
        flash('Usuario no encontrado.')
        return redirect(url_for('logout'))

    page_id = user.get('page_id')
    reseñas = list(mongo.db.reseñas.find({'page_id': page_id}).sort('fecha', -1))

    return render_template('admin_reseñas.html', reseñas=reseñas)

@app.route('/admin/reviews/delete/<review_id>', methods=['POST'])
@require_lifetime
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