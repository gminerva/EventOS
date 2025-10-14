def generar_y_guardar_qr(nombre, apellido, numerocedula, prefijo, numerotelefono, ImagenEntrada, NombreEvento):
    import qrcode
    import random
    import pyodbc
    from PIL import Image, ImageDraw, ImageFont
    from io import BytesIO
    import pywhatkit as pwk
    import os  # Importa os para eliminar archivos temporales
    from flask import Flask
    letras = "abcdefghijklmnñopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numeros = "0123456789"
    app = Flask(__name__)

    def generar_CodigoQR():
        unir = f"{letras}{numeros}"
        longitud = 8
        extension = random.sample(unir, longitud)
        CodigoQR = "".join(extension)
        return CodigoQR

    def crear_EntradaQR(CodigoQR):
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=22, border=1)
        qr.add_data(CodigoQR)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(f"{CodigoQR}.png")

        ruta_imagen = os.path.join(app.root_path, 'static', 'images', ImagenEntrada)

        im1 = Image.open(ruta_imagen)
        im2 = Image.open(f"{CodigoQR}.png")
        im1.paste(im2, (340, 1160))
        im1.save(f"{CodigoQR}.png")

        image = Image.open(f"{CodigoQR}.png")
        draw = ImageDraw.Draw(image)
        font = ImageFont.truetype("impact.ttf", 45)

        texto_codigo = f"{CodigoQR}"
        texto_usuario = f"{nombre} {apellido}\n{numerocedula}"

        # Tamaño de la imagen
        ancho_imagen, alto_imagen = image.size

        # Obtener el tamaño del texto usando ImageFont.getsize()
        ancho_texto_codigo, alto_texto_codigo = font.getsize(texto_codigo)
        ancho_texto_usuario, alto_texto_usuario = font.getsize(texto_usuario)

        # Coordenadas para centrar el texto
        x_codigo = (ancho_imagen - ancho_texto_codigo) // 2
        y_codigo = 1710  # Mantener la coordenada Y original para el código QR

        x_usuario = (ancho_imagen - ancho_texto_usuario) // 2
        y_usuario = 1810  # Mantener la coordenada Y original para el nombre y cédula

        # Dibujar el texto centrado
        draw.text((x_codigo, y_codigo), texto_codigo, font=font, fill="black", align="center")
        draw.multiline_text((x_usuario, y_usuario), texto_usuario, font=font, fill="black", align="center")

        # Guardar la imagen final en un buffer
        buffered = BytesIO()
        image.save(buffered, format="PNG")
        img_str = buffered.getvalue()
        return img_str

    CodigoQR = generar_CodigoQR()
    img_str = crear_EntradaQR(CodigoQR)

    try:
        connection = pyodbc.connect('DRIVER={SQL SERVER};'
                                    'SERVER=LAPTOP-L34EUPLC\\SQLEXPRESS;'
                                    'DATABASE=EntradaQR;'
                                    'UID=sa;'
                                    'PWD=ssgadmin;')
        print("CONEXIÓN EXITOSA A BASE DE DATOS")

        cursorInsert = connection.cursor()

        consultaSQL = "INSERT INTO dbo.TablaQR(Nombre,Apellido,NumeroCedula,NumeroTelefono,CodigoUnico,ImageQR,Estado) values (?,?,?,?,?,?,?);"
        cursorInsert.execute(consultaSQL, nombre, apellido, numerocedula, f"{prefijo}{numerotelefono}", CodigoQR, img_str, 0)

        cursorInsert.commit()
    except Exception as ex:
        print(ex)
    finally:
        cursorInsert.close()
        print("DATOS CARGADOS CORRECTAMENTE EN BASE DE DATOS")

    conn = pyodbc.connect('DRIVER={SQL SERVER};'
                          'SERVER=LAPTOP-L34EUPLC\\SQLEXPRESS;'
                          'DATABASE=EntradaQR;'
                          'UID=sa;'
                          'PWD=ssgadmin;')

    cursor = conn.cursor()

    cursor.execute("SELECT TOP 1 ImageQR FROM dbo.TablaQR ORDER BY idNumeroEntrada DESC")
    img = cursor.fetchone()[0]

    if img:
        # Guardar la imagen en un archivo temporal
        temp_image_path = "temp_image.png"
        with open(temp_image_path, "wb") as f:
            f.write(img)

        # Preparar los datos para el envío
        contact_no = f"{prefijo}{numerotelefono}"
        full_name = f"{nombre} {apellido}"
        caption = f"Hola {full_name}!, esta es tu entrada para {NombreEvento}"

        # Enviar la imagen
        pwk.sendwhats_image(contact_no, temp_image_path,caption,70,False,3)
        print("Imagen enviada exitosamente")
    
        # Eliminar el archivo temporal después de enviarlo
        os.remove(temp_image_path)
        conn.close()
        return True

    else:
        print("No se encontró ninguna imagen en la base de datos.")
        conn.close()
        return False

if __name__ == "__main__":
    generar_y_guardar_qr()


