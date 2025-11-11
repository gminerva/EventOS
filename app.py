from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
import uuid
from functools import wraps
import os
from werkzeug.utils import secure_filename

from urllib.parse import quote
import qrcode
from PIL import Image, ImageDraw, ImageFont
import pywhatkit as pwk

# =========================================================
# Helpers generales
# =========================================================

def normalizar_telefono_py(raw: str) -> str:
    """Devuelve +5959XXXXXXXX a partir de 098x..., 981..., 595..., +595..."""
    raw = str(raw or "")
    import re as _re
    digits = _re.sub(r"\D", "", raw)
    if not digits:
        return "+595"
    if digits.startswith("595"):
        return "+" + digits
    if digits.startswith("0"):
        digits = digits[1:]
    return "+595" + digits

# Alias por compatibilidad con código previo
def normalizar_telefono(raw: str) -> str:
    return normalizar_telefono_py(raw)

def hash_file(path: str) -> str:
    """Hash SHA-256 del archivo para identificar configuraciones por contenido."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def conectar_bd():
    conexion = sqlite3.connect("BDATA.db")
    conexion.row_factory = sqlite3.Row
    return conexion

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def rows_to_dicts(rows):
    return [dict(row) for row in rows] if rows else []

def verificar_sesion(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def solo_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "usuario_id" not in session or session.get("rol") != "admin":
            flash("Acceso restringido a Administradores.", "danger")
            return redirect(url_for("inicio"))
        return f(*args, **kwargs)
    return wrapper

def staff_o_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "usuario_id" not in session or session.get("rol") not in ["staff","admin"]:
            flash("Acceso restringido a Staff/Admin.", "danger")
            return redirect(url_for("inicio"))
        return f(*args, **kwargs)
    return wrapper

# =========================================================
# Configuración por plantilla (UI + Persistencia)
# =========================================================

def cargar_config_por_imagen(path_base: str):
    """
    Carga la configuración guardada (posiciones normalizadas en %) para la imagen base dada.
    Devuelve un dict con keys: qr, codigo, nombre, cedula, colores y tamaños.
    """
    try:
        fhash = hash_file(path_base)
        conexion = conectar_bd(); conexion.row_factory = sqlite3.Row
        cur = conexion.cursor()
        row = cur.execute("SELECT * FROM plantilla_config WHERE file_hash=?", (fhash,)).fetchone()
        conexion.close()
        if not row:
            return None
        return {
            'qr':     {'x': row['qr_x'],     'y': row['qr_y'],     'size': row['qr_size']},
            'codigo': {'x': row['codigo_x'], 'y': row['codigo_y'], 'size': row['codigo_size']},
            'nombre': {'x': row['nombre_x'], 'y': row['nombre_y'], 'size': row['nombre_size']},
            'cedula': {'x': row['cedula_x'], 'y': row['cedula_y'], 'size': row['cedula_size']},
            'text_fill':  row['text_fill']  if 'text_fill'  in row.keys() else '#FFFFFF',
            'text_stroke':row['text_stroke']if 'text_stroke'in row.keys() else '#000000',
            'stroke_w':   row['stroke_w']   if 'stroke_w'   in row.keys() else 3
        }
    except Exception:
        return None

# =========================================================
# Render final de la entrada con QR + textos
# =========================================================
def render_entrada_qr(codigo: str, cliente: str, evento: dict, tipo_entrada: dict, cedula: str = "") -> str:
    """Genera PNG final con QR y textos sobre la base, usando la configuración si existe."""

    # --- Generar QR temporal ---
    os.makedirs(os.path.join('static', 'qr'), exist_ok=True)
    qr_path = os.path.join('static', 'qr', f"{codigo}.png")
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=2)
    qr.add_data(codigo)
    qr.make(fit=True)
    img_qr = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
    img_qr.save(qr_path)

    # --- Elegir plantilla base: preferir la última subida en static/plantillas/actual_* ---
    plantilla_dir = os.path.join('static', 'plantillas')
    plantilla = os.path.join('plantillas', 'entrada_base.png.png')  # fallback original
    if os.path.exists(plantilla_dir):
        for fname in os.listdir(plantilla_dir):
            if fname.startswith('actual_'):
                plantilla = os.path.join(plantilla_dir, fname)
                break
    if not os.path.exists(plantilla):
        # Fallback final si no existe la base
        plantilla = os.path.join('pruebaentrada1.png') if os.path.exists('pruebaentrada1.png') else qr_path

    base = Image.open(plantilla).convert("RGBA")
    W, H = base.size

    # --- Cargar configuración guardada (si existe) ---
    cfg = cargar_config_por_imagen(plantilla)

    # --- Preparación de QR (tamaño) ---
    if cfg:
        qr_w = int(W * (float(cfg['qr'].get('size', 30)) / 100.0))
    else:
        qr_w = int(W * 0.42)  # comportamiento anterior

    ratio = qr_w / img_qr.width
    qr_h = int(img_qr.height * ratio)
    img_qr2 = img_qr.resize((qr_w, qr_h), Image.NEAREST)

    # --- Posición del QR ---
    if cfg:
        # x/y representan el centro del QR en %
        qrx = int(W * (float(cfg['qr']['x']) / 100.0)) - qr_w // 2
        qry = int(H * (float(cfg['qr']['y']) / 100.0)) - qr_h // 2
    else:
        # comportamiento previo (centrado aprox. en 0.67H)
        qrx = (W - qr_w) // 2
        qry = int(H * 0.67) - qr_h // 2

    base.paste(img_qr2, (qrx, qry), img_qr2)
    draw = ImageDraw.Draw(base)

    # --- Fuentes ---
    font_candidates = [
        "arialbd.ttf",
        "Arial Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    ]
    font_big = font_mid = None
    for f in font_candidates:
        try:
            # Tamaños por defecto (si no hay config)
            default_codigo_pct = 4.5
            default_texto_pct  = 4.0

            size_codigo_px = int(W * ((cfg['codigo']['size'] if cfg else default_codigo_pct)/100.0)) if cfg else int(W * (default_codigo_pct/100.0))
            size_texto_px  = int(W * ((cfg['nombre']['size'] if cfg else default_texto_pct)/100.0))  if cfg else int(W * (default_texto_pct/100.0))

            font_big = ImageFont.truetype(f, size=size_codigo_px)  # código
            font_mid = ImageFont.truetype(f, size=size_texto_px)   # nombre/cédula
            break
        except Exception:
            continue
    if font_big is None:
        font_big = ImageFont.load_default()
        font_mid = ImageFont.load_default()

    # --- Textos ---
    code_text = codigo
    name_text = cliente or ""
    ced_text  = cedula or ""

    if cfg:
        # Convertidor % -> px
        def PX(px_percent): return int(W * (float(px_percent) / 100.0))
        def PY(py_percent): return int(H * (float(py_percent) / 100.0))

        codigo_pos = (PX(cfg['codigo']['x']), PY(cfg['codigo']['y']))
        nombre_pos = (PX(cfg['nombre']['x']), PY(cfg['nombre']['y']))
        cedula_pos = (PX(cfg['cedula']['x']), PY(cfg['cedula']['y']))

        # Colores desde config
        fill_col   = cfg.get('text_fill', '#FFFFFF')
        stroke_col = cfg.get('text_stroke', '#000000')
        try:
            sw = int(float(cfg.get('stroke_w', 3)))
        except Exception:
            sw = 3

        def draw_label(text, pos, font, sw=3):
            x, y = pos
            # Anchor: esquina superior izquierda (coincide con canvas textBaseline=top)
            draw.text((x, y), text, fill=fill_col, font=font, stroke_width=sw, stroke_fill=stroke_col)

        draw_label(code_text,  codigo_pos, font_big, sw=sw)
        draw_label(name_text,  nombre_pos, font_mid, sw=max(1, sw-1))
        draw_label(ced_text,   cedula_pos, font_mid, sw=max(1, sw-1))

    else:
        # --- Sin config: mantener estilo anterior (centrado bajo QR) ---
        spacing = int(H * 0.02)
        y_text_code = qry + qr_h + spacing
        y_text_name = y_text_code + 94

        # Código centrado (negro con borde blanco)
        tw = draw.textlength(code_text, font=font_big)
        draw.text(
            ((W - tw) / 2, y_text_code),
            code_text,
            fill=(0, 0, 0, 255),
            font=font_big,
            stroke_width=3,
            stroke_fill=(255, 255, 255, 255)
        )

        # Nombre + cédula centrados
        line_h = getattr(font_mid, "size", int(W*0.04))
        l1w = draw.textlength(name_text, font=font_mid)
        l2w = draw.textlength(ced_text, font=font_mid)
        draw.text(
            ((W - l1w) / 2, y_text_name),
            name_text,
            fill=(0, 0, 0, 255),
            font=font_mid,
            stroke_width=2,
            stroke_fill=(255, 255, 255, 255)
        )
        draw.text(
            ((W - l2w) / 2, y_text_name + line_h + 8),
            ced_text,
            fill=(0, 0, 0, 255),
            font=font_mid,
            stroke_width=2,
            stroke_fill=(255, 255, 255, 255)
        )

    # --- Guardar imagen final ---
    out_dir = os.path.join('static', 'entradas_emitidas')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{codigo}.png")
    base.convert("RGB").save(out_path, "PNG")
    return out_path

# =========================================================
# App / Config
# =========================================================

app = Flask(__name__)
app.secret_key = "clave_secreta_segura_2024"

UPLOAD_FOLDER = os.path.join('static', 'images', 'entradas')
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def init_database():
    conn = sqlite3.connect('BDATA.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            nombre TEXT NOT NULL,
            apellido TEXT NOT NULL,
            rol TEXT NOT NULL CHECK (rol IN ('admin','staff')),
            activo INTEGER DEFAULT 1,
            fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS eventos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            fecha DATE NOT NULL,
            ubicacion TEXT NOT NULL,
            usuario_creador INTEGER,
            activo INTEGER DEFAULT 1,
            fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (usuario_creador) REFERENCES usuarios(id)
        )
    ''')


    #"prueba de commit"

#PRUEBA3
     #prueba 2
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tipos_entradas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            precio REAL NOT NULL,
            evento_id INTEGER NOT NULL,
            imagen_path TEXT,
            activo INTEGER DEFAULT 1,
            fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evento_id) REFERENCES eventos(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS entradas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo_qr TEXT NOT NULL,
            usuario_id INTEGER,
            estado TEXT,
            evento_id INTEGER,
            FOREIGN KEY(evento_id) REFERENCES eventos(id),
            FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS entradas_vendidas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo_qr TEXT NOT NULL,
            nombre_cliente TEXT NOT NULL,
            apellido_cliente TEXT NOT NULL,
            cedula_cliente TEXT NOT NULL,
            telefono_cliente TEXT NOT NULL,
            tipo_entrada_id INTEGER NOT NULL,
            evento_id INTEGER NOT NULL,
            precio_venta REAL NOT NULL,
            estado TEXT DEFAULT 'VIGENTE',
            fecha_venta DATETIME DEFAULT CURRENT_TIMESTAMP,
            fecha_uso DATETIME,
            usuario_vendedor INTEGER,
            FOREIGN KEY (tipo_entrada_id) REFERENCES tipos_entradas(id),
            FOREIGN KEY (evento_id) REFERENCES eventos(id),
            FOREIGN KEY (usuario_vendedor) REFERENCES usuarios(id)
        )
    ''')

    # NUEVO: tabla de configuración por plantilla (posiciones y tamaño QR/textos en % + colores)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS plantilla_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash TEXT UNIQUE,
            file_name TEXT,
            qr_x REAL, qr_y REAL, qr_size REAL,
            codigo_x REAL, codigo_y REAL, codigo_size REAL DEFAULT 4.5,
            nombre_x REAL, nombre_y REAL, nombre_size REAL DEFAULT 4.0,
            cedula_x REAL, cedula_y REAL, cedula_size REAL DEFAULT 4.0,
            text_fill TEXT DEFAULT '#FFFFFF',
            text_stroke TEXT DEFAULT '#000000',
            stroke_w REAL DEFAULT 3
        )
    ''')

    # Seed admin si no existe
    cursor.execute("SELECT COUNT(*) FROM usuarios WHERE rol = 'admin'")
    if cursor.fetchone()[0] == 0:
        admin_password = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute('''
            INSERT INTO usuarios (username, email, password, nombre, apellido, rol)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ("admin", "admin@sistema.com", admin_password, "Administrador", "Sistema", "admin"))

    conn.commit()
    conn.close()

def ensure_table_columns():
    """Migraciones suaves para columnas nuevas y un índice anti-duplicado útil."""
    con = sqlite3.connect('BDATA.db')
    cur = con.cursor()
    try:
        cur.execute("PRAGMA table_info(plantilla_config)")
        cols = [r[1] for r in cur.fetchall()]
        need = []
        if 'text_fill' not in cols:   need.append("ALTER TABLE plantilla_config ADD COLUMN text_fill TEXT DEFAULT '#FFFFFF'")
        if 'text_stroke' not in cols: need.append("ALTER TABLE plantilla_config ADD COLUMN text_stroke TEXT DEFAULT '#000000'")
        if 'stroke_w' not in cols:    need.append("ALTER TABLE plantilla_config ADD COLUMN stroke_w REAL DEFAULT 3")
        if 'codigo_size' not in cols: need.append("ALTER TABLE plantilla_config ADD COLUMN codigo_size REAL DEFAULT 4.5")
        if 'nombre_size' not in cols: need.append("ALTER TABLE plantilla_config ADD COLUMN nombre_size REAL DEFAULT 4.0")
        if 'cedula_size' not in cols: need.append("ALTER TABLE plantilla_config ADD COLUMN cedula_size REAL DEFAULT 4.0")
        for sql in need:
            try: cur.execute(sql)
            except Exception: pass
    except Exception:
        pass
    try:
        cur.execute("""CREATE INDEX IF NOT EXISTS idx_ev_dupe 
                       ON entradas_vendidas(nombre_cliente, apellido_cliente, cedula_cliente, telefono_cliente, tipo_entrada_id, evento_id, fecha_venta)""")
    except Exception:
        pass
    con.commit(); con.close()

# =========================================================
# Rutas básicas (login / inicio / etc)
# =========================================================

@app.route("/", methods=["GET", "POST"])
def raiz():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form["username"].strip()
        password = hash_password(request.form["password"].strip())

        conexion = conectar_bd()
        cursor = conexion.cursor()
        cursor.execute("""
            SELECT * FROM usuarios 
            WHERE (username = ? OR email = ?) AND password = ? AND activo = 1
        """, (username_or_email, username_or_email, password))
        user = cursor.fetchone()
        conexion.close()

        if user:
            session["usuario_id"] = user["id"]
            session["username"] = user["username"]
            session["nombre"] = user["nombre"]
            session["apellido"] = user["apellido"]
            session["rol"] = user["rol"]
            return redirect(url_for("inicio"))
        else:
            flash("Usuario/contraseña inválidos o usuario inactivo", "danger")
    return render_template("login.html")

@app.route("/inicio")
@verificar_sesion
def inicio():
    return render_template("inicio.html", usuario=session, rol=session["rol"])

@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada correctamente", "info")
    return redirect(url_for("login"))

# =========================================================
# VENTAS
# =========================================================

@app.route("/ventas")
@staff_o_admin
def ventas():
    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("SELECT id, nombre FROM eventos WHERE activo = 1")
    eventos = rows_to_dicts(cursor.fetchall())

    cursor.execute("""
        SELECT ev.*, e.nombre as evento_nombre, te.nombre as tipo_entrada_nombre
        FROM entradas_vendidas ev
        JOIN eventos e ON ev.evento_id = e.id
        JOIN tipos_entradas te ON ev.tipo_entrada_id = te.id
        ORDER BY ev.fecha_venta DESC
        LIMIT 25
    """)
    ventas = rows_to_dicts(cursor.fetchall())
    conexion.close()

    # ---- NONCE anti-doble envío ----
    nonce = uuid.uuid4().hex
    session['venta_nonce'] = nonce
    return render_template("ventas.html",
                           eventos=eventos,
                           ventas=ventas,
                           usuario=session,
                           rol=session["rol"],
                           venta_nonce=nonce)

@app.route("/obtener_entradas/<int:evento_id>")
@staff_o_admin
def obtener_entradas(evento_id):
    conexion = conectar_bd()
    cursor = conexion.cursor()
    cursor.execute("""
        SELECT id, nombre, precio 
        FROM tipos_entradas 
        WHERE evento_id = ? AND activo = 1
    """, (evento_id,))
    entradas = cursor.fetchall()
    conexion.close()

    if not entradas:
        return jsonify({'mensaje': 'No existen entradas para este evento'}), 404

    entradas_list = [{"id": r["id"], "nombre": r["nombre"], "precio": r["precio"]} for r in entradas]
    return jsonify(entradas_list)

@app.route("/nueva_venta", methods=["POST"])
@staff_o_admin
def nueva_venta():
    try:
        # ---- anti-doble envío ----
        nonce = request.form.get("venta_nonce")
        last = session.pop('venta_nonce', None)
        if (not nonce) or (nonce != last):
            flash("Este formulario ya fue procesado o es inválido. Refresca la página.", "warning")
            return redirect(url_for("ventas"))

        nombre = request.form["nombre"].strip()
        apellido = request.form["apellido"].strip()
        cedula = request.form["cedula"].strip()
        telefono = request.form["telefono"].strip()
        tipo_entrada_id = int(request.form["tipo_entrada_id"])
        evento_id = int(request.form["evento_id"])

        import random, string
        codigo_qr = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

        con = conectar_bd()
        cur = con.cursor()

        cur.execute("SELECT precio, nombre FROM tipos_entradas WHERE id = ?", (tipo_entrada_id,))
        te = cur.fetchone()
        if not te:
            raise ValueError("Tipo de entrada no encontrado")
        precio = float(te["precio"])
        nombre_tipo = te["nombre"]

        cur.execute("SELECT nombre, fecha, ubicacion FROM eventos WHERE id = ?", (evento_id,))
        ev = cur.fetchone()
        if not ev:
            raise ValueError("Evento no encontrado")
        nombre_evento = ev["nombre"]; fecha_evento = ev["fecha"]; ubicacion_evento = ev["ubicacion"]

        # --- Anti-duplicado adicional: misma persona + tipo + evento en los últimos 2 minutos ---
        cur.execute("""
            SELECT id, codigo_qr FROM entradas_vendidas
            WHERE nombre_cliente=? AND apellido_cliente=? AND cedula_cliente=? AND telefono_cliente=?
              AND tipo_entrada_id=? AND evento_id=? AND datetime(fecha_venta) >= datetime('now','-2 minutes')
            ORDER BY id DESC LIMIT 1
        """, (nombre, apellido, cedula, telefono, tipo_entrada_id, evento_id))
        reciente = cur.fetchone()
        if reciente:
            con.close()
            flash("Venta ya registrada recientemente; se evitó el duplicado.", "warning")
            return redirect(url_for("ventas"))

        cur.execute("""
            INSERT INTO entradas_vendidas 
            (codigo_qr, nombre_cliente, apellido_cliente, cedula_cliente, telefono_cliente, 
             tipo_entrada_id, evento_id, precio_venta, usuario_vendedor)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (codigo_qr, nombre, apellido, cedula, telefono, tipo_entrada_id,
              evento_id, precio, session["usuario_id"]))
        con.commit(); con.close()

        img_path = render_entrada_qr(
            codigo=codigo_qr,
            cliente=f"{nombre} {apellido}",
            evento={"nombre": nombre_evento, "fecha": fecha_evento, "ubicacion": ubicacion_evento},
            tipo_entrada={"nombre": nombre_tipo},
            cedula=cedula
        )

        numero = normalizar_telefono_py(telefono)
        caption = (
            f"¡Hola {nombre}! Esta es tu entrada para '{nombre_evento}'.\n"
            f"Fecha: {fecha_evento} | Lugar: {ubicacion_evento}\n"
            f"Tipo: {nombre_tipo} | Código: {codigo_qr}"
        )
        try:
            pwk.sendwhats_image(numero, img_path, caption, wait_time=20, tab_close=True, close_time=8)
            flash("Venta registrada y WhatsApp abierto para enviar la entrada.", "success")
        except Exception:
            wa_fallback = f"https://web.whatsapp.com/send?phone={numero.replace('+','')}&text=" + quote(caption)
            return render_template("whatsapp_redirect.html",
                                   wa_url=wa_fallback,
                                   qr_img_url=url_for('static', filename=f"entradas_emitidas/{codigo_qr}.png", _external=True),
                                   codigo_qr=codigo_qr,
                                   cliente=f"{nombre} {apellido}")
    except Exception as e:
        flash(f"Error al procesar la venta: {e}", "danger")
    return redirect(url_for("ventas"))

# =========================================================
# ESCANEAR / ESTADÍSTICAS / ADMIN
# =========================================================

@app.route("/escanear")
@staff_o_admin
def escanear():
    return render_template("escanear.html", usuario=session, rol=session["rol"])

@app.route("/verificar_entrada", methods=["POST"])
@staff_o_admin
def verificar_entrada():
    codigo_qr = request.json.get("codigo_qr")

    conexion = conectar_bd()
    cursor = conexion.cursor()
    cursor.execute("""
        SELECT ev.*, e.nombre as evento_nombre, te.nombre as tipo_entrada_nombre
        FROM entradas_vendidas ev
        JOIN eventos e ON ev.evento_id = e.id
        JOIN tipos_entradas te ON ev.tipo_entrada_id = te.id
        WHERE ev.codigo_qr = ?
    """, (codigo_qr,))
    entrada = cursor.fetchone()

    if not entrada:
        return jsonify({"valida": False, "mensaje": "Entrada no encontrada"})

    if entrada["estado"] == "UTILIZADA":
        return jsonify({"valida": False, "mensaje": "Entrada ya utilizada"})

    if entrada["estado"] == "CANCELADA":
        return jsonify({"valida": False, "mensaje": "Entrada cancelada"})

    cursor.execute("""
        UPDATE entradas_vendidas 
        SET estado = 'UTILIZADA', fecha_uso = CURRENT_TIMESTAMP 
        WHERE codigo_qr = ?
    """, (codigo_qr,))
    conexion.commit()
    conexion.close()

    return jsonify({"valida": True, "mensaje": "Entrada válida. ¡Bienvenido!"})

@app.route("/estadisticas")
@solo_admin
def estadisticas():
    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM usuarios WHERE activo = 1")
    total_usuarios = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as total FROM eventos WHERE activo = 1")
    total_eventos = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as total FROM entradas_vendidas WHERE estado = 'UTILIZADA'")
    total_utilizadas = cursor.fetchone()["total"]

    conexion.close()

    return render_template("estadisticas.html",
                           total_usuarios=total_usuarios,
                           total_eventos=total_eventos,
                           total_utilizadas=total_utilizadas,
                           usuario=session,
                           rol=session["rol"])

# =========================================================
# ADMIN: Usuarios
# =========================================================

@app.route("/gestionar_usuarios")
@solo_admin
def gestionar_usuarios():
    conexion = conectar_bd()
    cursor = conexion.cursor()
    cursor.execute("SELECT * FROM usuarios ORDER BY fecha_creacion DESC")
    usuarios = rows_to_dicts(cursor.fetchall())
    conexion.close()

    return render_template("gestionar_usuarios.html",
                           usuarios=usuarios,
                           usuario=session,
                           rol=session["rol"])

@app.route("/crear_usuario", methods=["POST"])
@solo_admin
def crear_usuario():
    try:
        username = request.form["username"]
        email = request.form["email"]
        password = hash_password(request.form["password"])
        nombre = request.form["nombre"]
        apellido = request.form["apellido"]
        rol = request.form["rol"]

        conexion = conectar_bd()
        cursor = conexion.cursor()
        cursor.execute("""
            INSERT INTO usuarios (username, email, password, nombre, apellido, rol)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, email, password, nombre, apellido, rol))
        conexion.commit()
        conexion.close()

        flash("Usuario creado correctamente", "success")
    except sqlite3.IntegrityError:
        flash("El usuario o email ya existe", "danger")
    except Exception as e:
        flash(f"Error al crear usuario: {e}", "danger")

    return redirect(url_for("gestionar_usuarios"))


# =========================================================
# ADMIN: Eventos
# =========================================================

@app.route("/gestionar_eventos")
@solo_admin
def gestionar_eventos():
    conexion = conectar_bd()
    cursor = conexion.cursor()
    cursor.execute("""
        SELECT e.*, u.nombre || ' ' || u.apellido as creador_nombre
        FROM eventos e
        JOIN usuarios u ON e.usuario_creador = u.id
        ORDER BY e.fecha DESC
    """)
    eventos = rows_to_dicts(cursor.fetchall())
    conexion.close()
    return render_template("gestionar_eventos.html",
                           eventos=eventos,
                           usuario=session,
                           rol=session["rol"])

@app.route("/crear_evento", methods=["POST"])
@solo_admin
def crear_evento():
    try:
        nombre = request.form["nombre"]
        fecha = request.form["fecha"]
        ubicacion = request.form["ubicacion"]

        conexion = conectar_bd()
        cursor = conexion.cursor()
        cursor.execute("""
            INSERT INTO eventos (nombre, fecha, ubicacion, usuario_creador)
            VALUES (?, ?, ?, ?)
        """, (nombre, fecha, ubicacion, session["usuario_id"]))
        conexion.commit()
        conexion.close()

        flash("Evento creado correctamente", "success")
    except Exception as e:
        flash(f"Error al crear evento: {e}", "danger")
    return redirect(url_for("gestionar_eventos"))

@app.route("/editar_evento/<int:evento_id>", methods=["POST"])
@solo_admin
def editar_evento(evento_id):
    try:
        nombre = request.form.get("nombre")
        fecha = request.form.get("fecha")
        ubicacion = request.form.get("ubicacion")
        activo = request.form.get("activo")
        if activo is not None:
            activo = 1 if str(activo) in ("1", "true", "on") else 0

        conexion = conectar_bd()
        cursor = conexion.cursor()
        if activo is None:
            cursor.execute("UPDATE eventos SET nombre=?, fecha=?, ubicacion=? WHERE id=?",
                           (nombre, fecha, ubicacion, evento_id))
        else:
            cursor.execute("UPDATE eventos SET nombre=?, fecha=?, ubicacion=?, activo=? WHERE id=?",
                           (nombre, fecha, ubicacion, activo, evento_id))
        conexion.commit()
        conexion.close()
        flash("Evento actualizado correctamente", "success")
    except Exception as e:
        flash(f"Error al actualizar evento: {e}", "danger")
    return redirect(url_for("gestionar_eventos"))

@app.route("/activar_evento/<int:evento_id>", methods=["POST"])
@solo_admin
def activar_evento(evento_id):
    try:
        conexion = conectar_bd()
        cursor = conexion.cursor()
        cursor.execute("UPDATE eventos SET activo = 1 WHERE id = ?", (evento_id,))
        conexion.commit()
        conexion.close()
        flash("Evento activado.", "success")
    except Exception as e:
        flash(f"Error al activar evento: {e}", "danger")
    return redirect(url_for("gestionar_eventos"))

@app.route("/desactivar_evento/<int:evento_id>", methods=["POST"])
@solo_admin
def desactivar_evento(evento_id):
    try:
        conexion = conectar_bd()
        cursor = conexion.cursor()
        cursor.execute("UPDATE eventos SET activo = 0 WHERE id = ?", (evento_id,))
        conexion.commit()
        conexion.close()
        flash("Evento desactivado (no se puede usar mientras esté inactivo).", "info")
    except Exception as e:
        flash(f"Error al desactivar evento: {e}", "danger")
    return redirect(url_for("gestionar_eventos"))

@app.route("/eliminar_evento/<int:evento_id>", methods=["POST"])
@solo_admin
def eliminar_evento(evento_id):
    try:
        conexion = conectar_bd()
        cursor = conexion.cursor()

        # Verificar dependencias
        cursor.execute("SELECT COUNT(*) AS c FROM tipos_entradas WHERE evento_id = ?", (evento_id,))
        c_tipos = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) AS c FROM entradas WHERE evento_id = ?", (evento_id,))
        c_codigos = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) AS c FROM entradas_vendidas WHERE evento_id = ?", (evento_id,))
        c_vendidas = cursor.fetchone()["c"]

        if (c_tipos + c_codigos + c_vendidas) > 0:
            conexion.close()
            flash("No se puede eliminar: el evento tiene entradas/tipos/ventas asociadas. Desactívalo en su lugar.", "danger")
            return redirect(url_for("gestionar_eventos"))

        # Sin dependencias: eliminar
        cursor.execute("DELETE FROM eventos WHERE id = ?", (evento_id,))
        conexion.commit()
        conexion.close()
        flash("Evento eliminado definitivamente.", "success")
    except Exception as e:
        flash(f"Error al eliminar evento: {e}", "danger")
    return redirect(url_for("gestionar_eventos"))

# =========================================================
# ADMIN: Tipos de Entradas
# =========================================================

@app.route("/gestionar_entradas")
@solo_admin
def gestionar_entradas():
    conexion = conectar_bd()
    cursor = conexion.cursor()
    cursor.execute("""
        SELECT te.*, e.nombre as evento_nombre
        FROM tipos_entradas te
        JOIN eventos e ON te.evento_id = e.id
        ORDER BY e.fecha DESC, te.nombre
    """)
    tipos_entradas = rows_to_dicts(cursor.fetchall())

    cursor.execute("SELECT id, nombre FROM eventos WHERE activo IN (0,1)")
    eventos = rows_to_dicts(cursor.fetchall())
    conexion.close()

    return render_template("gestionar_entradas.html",
                           tipos_entradas=tipos_entradas,
                           eventos=eventos,
                           usuario=session,
                           rol=session["rol"])

@app.route("/crear_tipo_entrada", methods=["POST"])
@solo_admin
def crear_tipo_entrada():
    try:
        nombre = request.form["nombre"]
        precio = float(request.form["precio"])
        evento_id = int(request.form["evento_id"])
        imagen = request.files.get("imagen")
        imagen_path = None

        if imagen and imagen.filename and allowed_file(imagen.filename):
            filename = secure_filename(imagen.filename)
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            imagen.save(save_path)
            imagen_path = os.path.normpath(save_path).replace("\\", "/")

        conexion = conectar_bd()
        cursor = conexion.cursor()
        if imagen_path:
            cursor.execute("""
                INSERT INTO tipos_entradas (nombre, precio, evento_id, imagen_path)
                VALUES (?, ?, ?, ?)
            """, (nombre, precio, evento_id, imagen_path))
        else:
            cursor.execute("""
                INSERT INTO tipos_entradas (nombre, precio, evento_id)
                VALUES (?, ?, ?)
            """, (nombre, precio, evento_id))
        conexion.commit()
        conexion.close()

        flash("Tipo de entrada creado correctamente", "success")
    except Exception as e:
        flash(f"Error al crear tipo de entrada: {e}", "danger")
    return redirect(url_for("gestionar_entradas"))

@app.route("/editar_tipo_entrada/<int:tipo_id>", methods=["POST"])
@solo_admin
def editar_tipo_entrada(tipo_id):
    try:
        nombre = request.form.get("nombre")
        precio = request.form.get("precio")
        evento_id = request.form.get("evento_id")
        activo = 1 if request.form.get("activo") in ("on", "1", "true", "True") else 0

        imagen = request.files.get("imagen")
        imagen_path = None

        if imagen and imagen.filename and allowed_file(imagen.filename):
            filename = secure_filename(imagen.filename)
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            imagen.save(save_path)
            imagen_path = os.path.normpath(save_path).replace("\\", "/")

        conexion = conectar_bd()
        cursor = conexion.cursor()
        if imagen_path:
            cursor.execute("""
                UPDATE tipos_entradas 
                   SET nombre=?, precio=?, evento_id=?, imagen_path=?, activo=? 
                 WHERE id=?
            """, (nombre, float(precio), int(evento_id), imagen_path, activo, tipo_id))
        else:
            cursor.execute("""
                UPDATE tipos_entradas 
                   SET nombre=?, precio=?, evento_id=?, activo=? 
                 WHERE id=?
            """, (nombre, float(precio), int(evento_id), activo, tipo_id))
        conexion.commit()
        conexion.close()
        flash("Tipo de entrada actualizado correctamente", "success")
    except Exception as e:
        flash(f"Error al actualizar tipo de entrada: {e}", "danger")
    return redirect(url_for("gestionar_entradas"))

@app.route("/activar_tipo_entrada/<int:tipo_id>", methods=["POST"])
@solo_admin
def activar_tipo_entrada(tipo_id):
    try:
        conexion = conectar_bd()
        cursor = conexion.cursor()
        cursor.execute("UPDATE tipos_entradas SET activo = 1 WHERE id = ?", (tipo_id,))
        conexion.commit(); conexion.close()
        flash("Tipo de entrada activado.", "success")
    except Exception as e:
        flash(f"Error al activar tipo de entrada: {e}", "danger")
    return redirect(url_for("gestionar_entradas"))

@app.route("/desactivar_tipo_entrada/<int:tipo_id>", methods=["POST"])
@solo_admin
def desactivar_tipo_entrada(tipo_id):
    try:
        conexion = conectar_bd()
        cursor = conexion.cursor()
        cursor.execute("UPDATE tipos_entradas SET activo = 0 WHERE id = ?", (tipo_id,))
        conexion.commit(); conexion.close()
        flash("Tipo de entrada desactivado.", "info")
    except Exception as e:
        flash(f"Error al desactivar tipo de entrada: {e}", "danger")
    return redirect(url_for("gestionar_entradas"))

@app.route("/eliminar_tipo_entrada/<int:tipo_id>", methods=["POST"])
@solo_admin
def eliminar_tipo_entrada(tipo_id):
    try:
        conexion = conectar_bd()
        cursor = conexion.cursor()
        cursor.execute("DELETE FROM tipos_entradas WHERE id = ?", (tipo_id,))
        conexion.commit()
        conexion.close()
        flash("Tipo de entrada eliminado.", "success")
    except Exception as e:
        flash(f"Error al eliminar tipo de entrada: {e}", "danger")
    return redirect(url_for("gestionar_entradas"))

# =========================================================
# UI de configuración de plantilla (subida + sliders + guardar)
# =========================================================

@app.route("/plantilla/config", methods=["GET"])
@staff_o_admin
def configurar_plantilla():
    # QR demo (para vista previa)
    os.makedirs(os.path.join('static','qr'), exist_ok=True)
    demo_qr = os.path.join('static','qr','demo_qr.png')
    if not os.path.exists(demo_qr):
        qrd = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=2)
        qrd.add_data("DEMO1234")
        qrd.make(fit=True)
        img_qrd = qrd.make_image(fill_color="black", back_color="white").convert("RGBA")
        img_qrd.save(demo_qr)

    # Buscar base actual
    plantilla_path = None
    plantilla_hash = None
    plantilla_nombre = None
    pdir = os.path.join('static','plantillas')
    if os.path.exists(pdir):
        for fname in sorted(os.listdir(pdir)):
            if fname.startswith('actual_'):
                plantilla_path = os.path.join(pdir, fname)
                plantilla_nombre = fname
                plantilla_hash = hash_file(plantilla_path)
                break

    plantilla_url = url_for('static', filename=f'plantillas/{os.path.basename(plantilla_path)}') if plantilla_path else None

    return render_template(
        "config_plantilla.html",
        plantilla_url=plantilla_url,
        plantilla_hash=plantilla_hash,
        plantilla_nombre=plantilla_nombre,
        demo_codigo="DEMO1234",
        demo_nombre="Juan Pérez",
        demo_cedula="1234567"
    )

@app.route("/plantilla/upload", methods=["POST"])
@staff_o_admin
def subir_plantilla():
    file = request.files.get("plantilla")
    if not file:
        flash("No se envió archivo", "danger")
        return redirect(url_for("configurar_plantilla"))
    fn = secure_filename(file.filename)
    if not fn.lower().endswith((".png",".jpg",".jpeg")):
        flash("Formato no soportado. Usá PNG o JPG.", "danger")
        return redirect(url_for("configurar_plantilla"))

    pdir = os.path.join('static','plantillas')
    os.makedirs(pdir, exist_ok=True)
    save_path = os.path.join(pdir, fn)
    file.save(save_path)

    fhash = hash_file(save_path)
    ext = os.path.splitext(fn)[1].lower()
    new_name = f"actual_{fhash[:12]}{ext}"
    new_path = os.path.join(pdir, new_name)

    # limpiar previos "actual_"
    for prev in os.listdir(pdir):
        if prev.startswith("actual_"):
            try:
                os.remove(os.path.join(pdir, prev))
            except:
                pass
    os.replace(save_path, new_path)
    flash("Plantilla subida correctamente.", "success")
    return redirect(url_for("configurar_plantilla"))

@app.route("/plantilla/get_config")
@staff_o_admin
def obtener_config():
    file_hash = request.args.get("hash","")
    if not file_hash:
        return jsonify({"error":"hash requerido"}), 400
    conexion = conectar_bd(); conexion.row_factory = sqlite3.Row
    cursor = conexion.cursor()
    row = cursor.execute("SELECT * FROM plantilla_config WHERE file_hash=?", (file_hash,)).fetchone()
    conexion.close()
    if not row:
        return jsonify({"config": None})
    cfg = {
        "qr": {"x": row["qr_x"], "y": row["qr_y"], "size": row["qr_size"]},
        "codigo": {"x": row["codigo_x"], "y": row["codigo_y"], "size": row["codigo_size"]},
        "nombre": {"x": row["nombre_x"], "y": row["nombre_y"], "size": row["nombre_size"]},
        "cedula": {"x": row["cedula_x"], "y": row["cedula_y"], "size": row["cedula_size"]},
        "text_fill": row["text_fill"] if "text_fill" in row.keys() else "#FFFFFF",
        "text_stroke": row["text_stroke"] if "text_stroke" in row.keys() else "#000000",
        "stroke_w": row["stroke_w"] if "stroke_w" in row.keys() else 3
    }
    return jsonify({"config": cfg})

@app.route("/plantilla/save_config", methods=["POST"])
@staff_o_admin
def guardar_config():
    data = request.get_json(force=True, silent=True) or {}
    file_hash = data.get("hash")
    cfg = data.get("config", {})
    if not file_hash or not cfg:
        return jsonify({"error":"Datos incompletos"}), 400
    conexion = conectar_bd()
    cursor = conexion.cursor()
    cursor.execute("""
        INSERT INTO plantilla_config (file_hash, file_name, 
            qr_x, qr_y, qr_size, 
            codigo_x, codigo_y, codigo_size,
            nombre_x, nombre_y, nombre_size,
            cedula_x, cedula_y, cedula_size,
            text_fill, text_stroke, stroke_w)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(file_hash) DO UPDATE SET
            file_name=excluded.file_name,
            qr_x=excluded.qr_x, qr_y=excluded.qr_y, qr_size=excluded.qr_size,
            codigo_x=excluded.codigo_x, codigo_y=excluded.codigo_y, codigo_size=excluded.codigo_size,
            nombre_x=excluded.nombre_x, nombre_y=excluded.nombre_y, nombre_size=excluded.nombre_size,
            cedula_x=excluded.cedula_x, cedula_y=excluded.cedula_y, cedula_size=excluded.cedula_size,
            text_fill=excluded.text_fill, text_stroke=excluded.text_stroke, stroke_w=excluded.stroke_w
    """, (
        file_hash, "",
        float(cfg.get("qr",{}).get("x",70)),     float(cfg.get("qr",{}).get("y",35)),     float(cfg.get("qr",{}).get("size",30)),
        float(cfg.get("codigo",{}).get("x",70)), float(cfg.get("codigo",{}).get("y",68)), float(cfg.get("codigo",{}).get("size",4.5)),
        float(cfg.get("nombre",{}).get("x",28)), float(cfg.get("nombre",{}).get("y",68)), float(cfg.get("nombre",{}).get("size",4.0)),
        float(cfg.get("cedula",{}).get("x",28)), float(cfg.get("cedula",{}).get("y",78)), float(cfg.get("cedula",{}).get("size",4.0)),
        cfg.get("text_fill", "#FFFFFF"),
        cfg.get("text_stroke", "#000000"),
        float(cfg.get("stroke_w", 3))
    ))
    conexion.commit()
    conexion.close()
    return jsonify({"ok": True})

# =========================================================
# Main
# =========================================================

if __name__ == "__main__":
    init_database()
    ensure_table_columns()
    os.makedirs('static/images', exist_ok=True)
    app.run(debug=True, use_reloader=False)

# --- agregado por Juan: commit de mantenimiento ---

