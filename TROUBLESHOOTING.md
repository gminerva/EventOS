# Solución de problemas

## 1) PowerShell: no puedo activar el venv
Error: *la ejecución de scripts está deshabilitada*.
- Abrí PowerShell **como Administrador** y ejecutá:
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
- Volvé a: `.\.venv\Scripts\Activate.ps1`

## 2) Flask: ModuleNotFoundError: No module named 'flask'
- Activá el venv y corré: `pip install -r requirements.txt`

## 3) SQLite: database is locked
- Cerrá instancias en segundo plano que estén usando la DB.
- Evitá abrir la DB con otro programa mientras la app corre.

## 4) WhatsApp (pywhatkit)
- Si el envío falla, se abre un enlace fallback a **WhatsApp Web** para adjuntar manualmente.

## 5) Cámara/QR en navegador
- Revisá permisos de cámara y el selector de dispositivo en Escanear.
