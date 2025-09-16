from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = "clave_secreta_segura_2024"  # Cambiar en producción

# ------------------------------
# Configuración de la base de datos
# ------------------------------
def init_database():
    """Inicializa la base de datos con las tablas necesarias"""
    conn = sqlite3.connect('BDATA.db')
    cursor = conn.cursor()
    
    # Tabla de usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            nombre TEXT NOT NULL,
            apellido TEXT NOT NULL,
            rol TEXT NOT NULL CHECK(rol IN ('admin', 'staff')),
            activo INTEGER DEFAULT 1,
            fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de eventos
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
    
    # Tabla de tipos de entradas
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
    
    # Tabla de entradas vendidas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS entradas_vendidas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo_qr TEXT UNIQUE NOT NULL,
            nombre_cliente TEXT NOT NULL,
            apellido_cliente TEXT NOT NULL,
            cedula_cliente TEXT NOT NULL,
            telefono_cliente TEXT NOT NULL,
            tipo_entrada_id INTEGER NOT NULL,
            evento_id INTEGER NOT NULL,
            precio_venta REAL NOT NULL,
            estado TEXT DEFAULT 'VIGENTE' CHECK(estado IN ('VIGENTE', 'UTILIZADA', 'CANCELADA')),
            fecha_venta DATETIME DEFAULT CURRENT_TIMESTAMP,
            fecha_uso DATETIME NULL,
            usuario_vendedor INTEGER,
            FOREIGN KEY (tipo_entrada_id) REFERENCES tipos_entradas(id),
            FOREIGN KEY (evento_id) REFERENCES eventos(id),
            FOREIGN KEY (usuario_vendedor) REFERENCES usuarios(id)
        )
    ''')
    
    # Crear usuario admin por defecto
    cursor.execute("SELECT COUNT(*) FROM usuarios WHERE rol = 'admin'")
    if cursor.fetchone()[0] == 0:
        admin_password = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute('''
            INSERT INTO usuarios (username, email, password, nombre, apellido, rol)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ("admin", "admin@sistema.com", admin_password, "Administrador", "Sistema", "admin"))
    
    conn.commit()
    conn.close()

def conectar_bd():
    """Conecta a la base de datos"""
    conexion = sqlite3.connect("BDATA.db")
    conexion.row_factory = sqlite3.Row
    return conexion

def hash_password(password):
    """Encripta la contraseña"""
    return hashlib.sha256(password.encode()).hexdigest()

def rows_to_dicts(rows):
    """Convierte filas de SQLite a lista de diccionarios"""
    return [dict(row) for row in rows] if rows else []

def verificar_sesion(f):
    """Decorador para verificar si el usuario está logueado"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            flash("Debes iniciar sesión para acceder a esta página", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def solo_admin(f):
    """Decorador para restringir acceso solo a administradores"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            flash("Debes iniciar sesión para acceder a esta página", "warning")
            return redirect(url_for("login"))
        if session.get("rol") != "admin":
            flash("Acceso denegado: Se requieren permisos de administrador", "danger")
            return redirect(url_for("inicio"))
        return f(*args, **kwargs)
    return decorated_function

def staff_o_admin(f):
    """Decorador para restringir acceso a staff o admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            flash("Debes iniciar sesión para acceder a esta página", "warning")
            return redirect(url_for("login"))
        if session.get("rol") not in ["admin", "staff"]:
            flash("No tienes permisos para acceder a esta sección", "danger")
            return redirect(url_for("inicio"))
        return f(*args, **kwargs)
    return decorated_function

# ------------------------------
# RUTAS PRINCIPALES
# ------------------------------
@app.route("/")
def raiz():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])

        conexion = conectar_bd()
        cursor = conexion.cursor()
        cursor.execute("""
            SELECT id, username, nombre, apellido, rol, email 
            FROM usuarios 
            WHERE (username=? OR email=?) AND password=? AND activo=1
        """, (username, username, password))
        user = cursor.fetchone()
        conexion.close()

        if user:
            session["usuario_id"] = user["id"]
            session["username"] = user["username"]
            session["nombre"] = user["nombre"]
            session["apellido"] = user["apellido"]
            session["rol"] = user["rol"]
            session["email"] = user["email"]
            flash(f"Bienvenido {user['nombre']} {user['apellido']}", "success")
            return redirect(url_for("inicio"))
        else:
            flash("Usuario o contraseña incorrectos", "danger")

    return render_template("login.html")

@app.route("/inicio")
@verificar_sesion
def inicio():
    return render_template("inicio.html", 
                         usuario=session,
                         rol=session["rol"])

@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada correctamente", "info")
    return redirect(url_for("login"))

# ------------------------------
# RUTAS PARA STAFF Y ADMIN
# ------------------------------
@app.route("/ventas")
@staff_o_admin
def ventas():
    conexion = conectar_bd()
    cursor = conexion.cursor()
    
    # Obtener eventos activos
    cursor.execute("SELECT id, nombre FROM eventos WHERE activo = 1")
    eventos = rows_to_dicts(cursor.fetchall())
    
    # Obtener ventas recientes
    cursor.execute("""
        SELECT ev.*, e.nombre as evento_nombre, te.nombre as tipo_entrada_nombre
        FROM entradas_vendidas ev
        JOIN eventos e ON ev.evento_id = e.id
        JOIN tipos_entradas te ON ev.tipo_entrada_id = te.id
        ORDER BY ev.fecha_venta DESC
        LIMIT 50
    """)
    ventas = rows_to_dicts(cursor.fetchall())
    
    conexion.close()
    
    return render_template("ventas.html", 
                         eventos=eventos, 
                         ventas=ventas,
                         usuario=session,
                         rol=session["rol"])

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
    
    entradas_list = [
        {
            "id": entrada["id"], 
            "nombre": entrada["nombre"], 
            "precio": entrada["precio"]
        }
        for entrada in entradas
    ]
    
    return jsonify(entradas_list)

@app.route("/nueva_venta", methods=["POST"])
@staff_o_admin
def nueva_venta():
    try:
        # Recoger datos del formulario
        nombre = request.form["nombre"]
        apellido = request.form["apellido"]
        cedula = request.form["cedula"]
        telefono = request.form["telefono"]
        tipo_entrada_id = request.form["tipo_entrada_id"]
        evento_id = request.form["evento_id"]
        
        # Generar código QR único
        import random
        import string
        codigo_qr = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
        conexion = conectar_bd()
        cursor = conexion.cursor()
        
        # Obtener precio de la entrada
        cursor.execute("SELECT precio FROM tipos_entradas WHERE id = ?", (tipo_entrada_id,))
        precio = cursor.fetchone()["precio"]
        
        # Insertar venta
        cursor.execute("""
            INSERT INTO entradas_vendidas 
            (codigo_qr, nombre_cliente, apellido_cliente, cedula_cliente, telefono_cliente, 
             tipo_entrada_id, evento_id, precio_venta, usuario_vendedor)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (codigo_qr, nombre, apellido, cedula, telefono, tipo_entrada_id, 
              evento_id, precio, session["usuario_id"]))
        
        conexion.commit()
        conexion.close()
        
        flash("Venta registrada correctamente", "success")
        # Aquí se podría integrar el envío por WhatsApp
        
    except Exception as e:
        flash(f"Error al procesar la venta: {str(e)}", "danger")
    
    return redirect(url_for("ventas"))

@app.route("/escanear")
@staff_o_admin
def escanear():
    return render_template("escanear.html", 
                         usuario=session,
                         rol=session["rol"])

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
    
    # Marcar como utilizada
    cursor.execute("""
        UPDATE entradas_vendidas 
        SET estado = 'UTILIZADA', fecha_uso = CURRENT_TIMESTAMP 
        WHERE codigo_qr = ?
    """, (codigo_qr,))
    conexion.commit()
    conexion.close()
    
    return jsonify({
        "valida": True, 
        "mensaje": "Entrada válida - Acceso permitido",
        "cliente": f"{entrada['nombre_cliente']} {entrada['apellido_cliente']}",
        "evento": entrada["evento_nombre"],
        "tipo_entrada": entrada["tipo_entrada_nombre"]
    })

# ------------------------------
# RUTAS SOLO PARA ADMIN
# ------------------------------
@app.route("/estadisticas")
@solo_admin
def estadisticas():
    conexion = conectar_bd()
    cursor = conexion.cursor()
    
    # Estadísticas básicas
    cursor.execute("SELECT COUNT(*) as total FROM entradas_vendidas WHERE estado != 'CANCELADA'")
    total_ventas = cursor.fetchone()["total"]
    
    cursor.execute("SELECT SUM(precio_venta) as total FROM entradas_vendidas WHERE estado != 'CANCELADA'")
    total_ingresos = cursor.fetchone()["total"] or 0
    
    cursor.execute("SELECT COUNT(*) as total FROM entradas_vendidas WHERE estado = 'UTILIZADA'")
    total_utilizadas = cursor.fetchone()["total"]
    
    # Ventas por evento
    cursor.execute("""
        SELECT e.nombre, COUNT(*) as ventas, SUM(ev.precio_venta) as ingresos
        FROM entradas_vendidas ev
        JOIN eventos e ON ev.evento_id = e.id
        WHERE ev.estado != 'CANCELADA'
        GROUP BY e.id, e.nombre
    """)
    ventas_por_evento = rows_to_dicts(cursor.fetchall())
    
    conexion.close()
    
    return render_template("estadisticas.html",
                         total_ventas=total_ventas,
                         total_ingresos=total_ingresos,
                         total_utilizadas=total_utilizadas,
                         ventas_por_evento=ventas_por_evento,
                         usuario=session,
                         rol=session["rol"])

@app.route("/gestionar_usuarios")
@solo_admin
def gestionar_usuarios():
    conexion = conectar_bd()
    cursor = conexion.cursor()
    cursor.execute("""
        SELECT id, username, email, nombre, apellido, rol, activo, fecha_creacion
        FROM usuarios 
        ORDER BY fecha_creacion DESC
    """)
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
        flash(f"Error al crear usuario: {str(e)}", "danger")
    
    return redirect(url_for("gestionar_usuarios"))

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
        flash(f"Error al crear evento: {str(e)}", "danger")
    
    return redirect(url_for("gestionar_eventos"))

@app.route("/gestionar_entradas")
@solo_admin
def gestionar_entradas():
    conexion = conectar_bd()
    cursor = conexion.cursor()
    cursor.execute("""
        SELECT te.*, e.nombre as evento_nombre
        FROM tipos_entradas te
        JOIN eventos e ON te.evento_id = e.id
        WHERE te.activo = 1
        ORDER BY e.fecha DESC, te.nombre
    """)
    tipos_entradas = rows_to_dicts(cursor.fetchall())
    
    cursor.execute("SELECT id, nombre FROM eventos WHERE activo = 1")
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
        evento_id = request.form["evento_id"]
        
        conexion = conectar_bd()
        cursor = conexion.cursor()
        cursor.execute("""
            INSERT INTO tipos_entradas (nombre, precio, evento_id)
            VALUES (?, ?, ?)
        """, (nombre, precio, evento_id))
        conexion.commit()
        conexion.close()
        
        flash("Tipo de entrada creado correctamente", "success")
        
    except Exception as e:
        flash(f"Error al crear tipo de entrada: {str(e)}", "danger")
    
    return redirect(url_for("gestionar_entradas"))

# ------------------------------
# MAIN
# ------------------------------
if __name__ == "__main__":
    # Inicializar la base de datos
    init_database()
    
    # Crear carpeta de uploads si no existe
    os.makedirs('static/images', exist_ok=True)
    
    app.run(debug=True)