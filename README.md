# EventOS

Aplicación Flask para gestión de eventos, venta y validación de entradas con QR. Genera imágenes de entrada (QR + plantilla) y permite enviar la entrada por WhatsApp.

- Código principal: [app.py](app.py)  
  - Generación de la imagen de entrada: [`app.render_entrada_qr`](app.py)  
  - Inicialización de la base de datos: [`app.init_database`](app.py) y migraciones suaves: [`app.ensure_table_columns`](app.py)  
  - Normalización de teléfonos: [`app.normalizar_telefono_py`](app.py)  
  - Conexión SQLite: [`app.conectar_bd`](app.py)  
  - Validación de archivos subidos: [`app.allowed_file`](app.py)  
  - Rutas importantes: [`app.ventas`](app.py), [`app.nueva_venta`](app.py), [`app.verificar_entrada`](app.py), [`app.configurar_plantilla`](app.py)

Otros ficheros relevantes:
- Integración / envío y guardado en SQL Server: [generar_qr_y_guardar_bd.py](generar_qr_y_guardar_bd.py) and [TareasEvento.py](TareasEvento.py)  
  - Llamada desde tareas: [`generar_y_guardar_qr`](generar_qr_y_guardar_bd.py)  
- Vistas principales:  
  - [templates/ventas.html](templates/ventas.html)  
  - [templates/Escanear.html](templates/Escanear.html)  
  - [templates/config_plantilla.html](templates/config_plantilla.html)  
  - [templates/whatsapp_redirect.html](templates/whatsapp_redirect.html)  
  - [templates/inicio.html](templates/inicio.html)  
- Scripts cliente para configuración de plantilla: [static/js/config_plantilla.js](static/js/config_plantilla.js)  
- Dependencias: [requirements.txt](requirements.txt)  
- Tests: [tests/](tests/)

## Requisitos
- Python 3.10+  
- Instalar dependencias:
```bash
pip install -r requirements.txt
```

## Inicializar y ejecutar (desarrollo)
1. Inicializar la BD y tablas (se crea admin semilla):
```bash
python app.py
```
El arranque ejecuta [`app.init_database`](app.py) y [`app.ensure_table_columns`](app.py) y levanta el servidor Flask.

2. Abrir en el navegador:
- http://127.0.0.1:5000

3. Credenciales semilla (ver [`app.init_database`](app.py)):
- usuario: `admin`  
- contraseña: `admin123` (se guarda hasheada en la BD)

## Flujo principal
- Vender entrada: panel Ventas -> formulario en [templates/ventas.html](templates/ventas.html). La ruta [`app.nueva_venta`](app.py) genera el código, guarda en `entradas_vendidas`, genera la imagen con [`app.render_entrada_qr`](app.py) y abre WhatsApp Web mediante pywhatkit (fallback a [templates/whatsapp_redirect.html](templates/whatsapp_redirect.html)).
- Escaneo/validación: interfaz en [templates/Escanear.html](templates/Escanear.html) que consulta [`app.verificar_entrada`](app.py) para validar y marcar entradas como `UTILIZADA`.
- Configurar plantilla: subir plantilla base y ajustar parámetros en [templates/config_plantilla.html](templates/config_plantilla.html) + [static/js/config_plantilla.js](static/js/config_plantilla.js). Guardado en tabla `plantilla_config` mediante [`app.guardar_config`](app.py) y leído por [`app.cargar_config_por_imagen`](app.py).

## Estructura de la BD (resumen)
Tablas principales creadas por [`app.init_database`](app.py):
- usuarios, eventos, tipos_entradas, entradas, entradas_vendidas, plantilla_config.

## Tests
Ejecutar tests con pytest:
```bash
pytest -q
```
Los tests usan BD temporal (ver [tests/test_app_py.py](tests/test_app_py.py)).

