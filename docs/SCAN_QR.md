# Escanear entradas (QR)

Esta pantalla permite validar entradas escaneando el **código QR** con la cámara.
- Si el QR existe y la entrada no fue usada: muestra **VÁLIDA** y marca la entrada como **UTILIZADA** (con `fecha_uso`).
- Si ya fue utilizada o está cancelada: muestra mensaje de **rechazo**.

## Requisitos
- Cámara web o app de cámara virtual (p. ej. iVCam / DroidCam).
- Permitir acceso a la cámara en el navegador.

## Pasos
1) Ir al menú **Escanear** e iniciar la cámara.
2) Apuntar al QR de la entrada.
3) Ver el resultado en pantalla:
   - Verde: *Entrada válida. ¡Bienvenido!*
   - Rojo: *Entrada ya utilizada* o *Entrada cancelada*.
4) La app actualiza el estado en `entradas_vendidas`.

## Solución de problemas
- **No aparece la cámara**: revisa permisos del navegador o cambia el dispositivo en el selector de cámara.
- **iVCam/DroidCam no se listan**: abrí primero la app externa y luego refrescá la página.
- **Luz o foco**: acercá/alejá el QR hasta que el escáner lo detecte.
