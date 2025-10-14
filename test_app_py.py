import pytest
import sqlite3
import os
import tempfile
import hashlib
from unittest.mock import Mock, patch, MagicMock
from flask import session
from PIL import Image
import io

# Importar la aplicación y funciones
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import (
    app, 
    normalizar_telefono_py, 
    normalizar_telefono,
    hash_file,
    conectar_bd,
    hash_password,
    rows_to_dicts,
    init_database,
    cargar_config_por_imagen,
    allowed_file
)


# ==================== FIXTURES ====================

@pytest.fixture
def client():
    """Cliente de prueba de Flask"""
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture
def temp_db():
    """Base de datos temporal para pruebas"""
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    
    # Configurar la app para usar la BD temporal
    original_db = 'BDATA.db'
    
    # Crear BD temporal
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Crear tablas necesarias
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
    
    # Insertar usuario admin para pruebas
    admin_password = hashlib.sha256("admin123".encode()).hexdigest()
    cursor.execute('''
        INSERT INTO usuarios (username, email, password, nombre, apellido, rol)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', ("admin_test", "admin@test.com", admin_password, "Admin", "Test", "admin"))
    
    # Insertar usuario staff para pruebas
    staff_password = hashlib.sha256("staff123".encode()).hexdigest()
    cursor.execute('''
        INSERT INTO usuarios (username, email, password, nombre, apellido, rol)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', ("staff_test", "staff@test.com", staff_password, "Staff", "Test", "staff"))
    
    conn.commit()
    conn.close()
    
    yield db_path
    
    # Cleanup
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def temp_image():
    """Imagen temporal para pruebas"""
    img = Image.new('RGB', (100, 100), color='red')
    img_path = tempfile.mktemp(suffix='.png')
    img.save(img_path)
    
    yield img_path
    
    if os.path.exists(img_path):
        os.unlink(img_path)


# ==================== TESTS FUNCIONES HELPERS ====================

class TestNormalizarTelefono:
    """Tests para normalización de teléfonos paraguayos"""
    
    def test_normalizar_con_codigo_pais(self):
        assert normalizar_telefono_py("+595981123456") == "+595981123456"
        assert normalizar_telefono_py("595981123456") == "+595981123456"
    
    def test_normalizar_sin_codigo_pais(self):
        assert normalizar_telefono_py("0981123456") == "+595981123456"
        assert normalizar_telefono_py("981123456") == "+595981123456"
    
    def test_normalizar_con_espacios(self):
        assert normalizar_telefono_py("0981 123 456") == "+595981123456"
        assert normalizar_telefono_py("+595 981 123456") == "+595981123456"
    
    def test_normalizar_con_guiones(self):
        assert normalizar_telefono_py("0981-123-456") == "+595981123456"
    
    def test_normalizar_vacio(self):
        assert normalizar_telefono_py("") == "+595"
        assert normalizar_telefono_py(None) == "+595"
    
    def test_alias_compatibilidad(self):
        # Verificar que ambas funciones hacen lo mismo
        assert normalizar_telefono("0981123456") == normalizar_telefono_py("0981123456")


class TestHashFile:
    """Tests para hash de archivos"""
    
    def test_hash_file_consistente(self, temp_image):
        hash1 = hash_file(temp_image)
        hash2 = hash_file(temp_image)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 produce 64 caracteres hex
    
    def test_hash_file_diferente_contenido(self, temp_image):
        hash1 = hash_file(temp_image)
        
        # Crear otro archivo con contenido diferente
        img2 = Image.new('RGB', (100, 100), color='blue')
        img2_path = tempfile.mktemp(suffix='.png')
        img2.save(img2_path)
        
        hash2 = hash_file(img2_path)
        
        assert hash1 != hash2
        
        os.unlink(img2_path)


class TestHashPassword:
    """Tests para hash de contraseñas"""
    
    def test_hash_password_consistente(self):
        password = "test123"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 == hash2
    
    def test_hash_password_diferente(self):
        hash1 = hash_password("password1")
        hash2 = hash_password("password2")
        assert hash1 != hash2
    
    def test_hash_password_longitud(self):
        hash_result = hash_password("test")
        assert len(hash_result) == 64  # SHA-256


class TestRowsToDicts:
    """Tests para conversión de rows a diccionarios"""
    
    def test_rows_to_dicts_vacio(self):
        assert rows_to_dicts([]) == []
        assert rows_to_dicts(None) == []
    
    def test_rows_to_dicts_con_datos(self, temp_db):
        conn = sqlite3.connect(temp_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM usuarios WHERE username = 'admin_test'")
        rows = cursor.fetchall()
        
        result = rows_to_dicts(rows)
        
        assert len(result) == 1
        assert isinstance(result[0], dict)
        assert result[0]['username'] == 'admin_test'
        
        conn.close()


class TestAllowedFile:
    """Tests para validación de archivos permitidos"""
    
    def test_allowed_file_validos(self):
        assert allowed_file("imagen.png") == True
        assert allowed_file("foto.jpg") == True
        assert allowed_file("picture.jpeg") == True
        assert allowed_file("image.webp") == True
    
    def test_allowed_file_invalidos(self):
        assert allowed_file("documento.pdf") == False
        assert allowed_file("archivo.txt") == False
        assert allowed_file("video.mp4") == False
        assert allowed_file("sinextension") == False
    
    def test_allowed_file_mayusculas(self):
        assert allowed_file("IMAGEN.PNG") == True
        assert allowed_file("Foto.JPG") == True


# ==================== TESTS RUTAS ====================

class TestRutasBasicas:
    """Tests para rutas básicas de la aplicación"""
    
    def test_raiz_redirect(self, client):
        response = client.get('/')
        assert response.status_code == 302  # Redirect
        assert '/login' in response.location
    
    def test_login_get(self, client):
        response = client.get('/login')
        assert response.status_code == 200
        assert b'login' in response.data.lower()
    
    @patch('app.conectar_bd')
    def test_login_post_exitoso(self, mock_db, client):
        # Mock de la base de datos
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Simular usuario encontrado
        mock_row = {
            'id': 1,
            'username': 'admin_test',
            'nombre': 'Admin',
            'apellido': 'Test',
            'rol': 'admin'
        }
        mock_cursor.fetchone.return_value = mock_row
        
        response = client.post('/login', data={
            'username': 'admin_test',
            'password': 'admin123'
        }, follow_redirects=False)
        
        assert response.status_code == 302
        assert '/inicio' in response.location
    
    def test_logout(self, client):
        with client.session_transaction() as sess:
            sess['usuario_id'] = 1
            sess['username'] = 'test'
        
        response = client.get('/logout', follow_redirects=False)
        assert response.status_code == 302
        
        with client.session_transaction() as sess:
            assert 'usuario_id' not in sess


class TestRutasProtegidas:
    """Tests para rutas que requieren autenticación"""
    
    def test_inicio_sin_sesion(self, client):
        response = client.get('/inicio', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.location
    
    def test_inicio_con_sesion(self, client):
        with client.session_transaction() as sess:
            sess['usuario_id'] = 1
            sess['username'] = 'test'
            sess['nombre'] = 'Test'
            sess['apellido'] = 'User'
            sess['rol'] = 'admin'
        
        response = client.get('/inicio')
        assert response.status_code == 200
    
    def test_ventas_sin_sesion(self, client):
        response = client.get('/ventas', follow_redirects=False)
        assert response.status_code == 302
    
    def test_escanear_sin_sesion(self, client):
        response = client.get('/escanear', follow_redirects=False)
        assert response.status_code == 302


class TestRutasAdmin:
    """Tests para rutas exclusivas de admin"""
    
    def test_estadisticas_sin_admin(self, client):
        with client.session_transaction() as sess:
            sess['usuario_id'] = 2
            sess['rol'] = 'staff'
        
        response = client.get('/estadisticas', follow_redirects=False)
        assert response.status_code == 302
    
    def test_gestionar_usuarios_sin_admin(self, client):
        with client.session_transaction() as sess:
            sess['usuario_id'] = 2
            sess['rol'] = 'staff'
        
        response = client.get('/gestionar_usuarios', follow_redirects=False)
        assert response.status_code == 302
    
    @patch('app.conectar_bd')
    def test_gestionar_usuarios_con_admin(self, mock_db, client):
        with client.session_transaction() as sess:
            sess['usuario_id'] = 1
            sess['rol'] = 'admin'
            sess['username'] = 'admin'
            sess['nombre'] = 'Admin'
            sess['apellido'] = 'Test'
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = []
        
        response = client.get('/gestionar_usuarios')
        assert response.status_code == 200


# ==================== TESTS INTEGRACIÓN ====================

class TestIntegracionVentas:
    """Tests de integración para el módulo de ventas"""
    
    @patch('app.conectar_bd')
    def test_obtener_entradas_evento_valido(self, mock_db, client):
        with client.session_transaction() as sess:
            sess['usuario_id'] = 1
            sess['rol'] = 'admin'
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        mock_entradas = [
            {'id': 1, 'nombre': 'VIP', 'precio': 100000},
            {'id': 2, 'nombre': 'General', 'precio': 50000}
        ]
        mock_cursor.fetchall.return_value = [
            MagicMock(__getitem__=lambda s, k: mock_entradas[0][k]),
            MagicMock(__getitem__=lambda s, k: mock_entradas[1][k])
        ]
        
        response = client.get('/obtener_entradas/1')
        
        assert response.status_code == 200
        data = response.get_json()
        assert len(data) == 2
    
    @patch('app.conectar_bd')
    def test_verificar_entrada_valida(self, mock_db, client):
        with client.session_transaction() as sess:
            sess['usuario_id'] = 1
            sess['rol'] = 'staff'
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        mock_entrada = {
            'codigo_qr': 'TEST1234',
            'estado': 'VIGENTE',
            'evento_nombre': 'Concierto Test',
            'tipo_entrada_nombre': 'VIP'
        }
        mock_row = MagicMock()
        mock_row.__getitem__ = lambda self, key: mock_entrada[key]
        mock_cursor.fetchone.return_value = mock_row
        
        response = client.post('/verificar_entrada',
                              json={'codigo_qr': 'TEST1234'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['valida'] == True


# ==================== MAIN ====================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
