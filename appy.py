from flask_mysqldb import MySQL
from config import Config
from models.user import register_user, aes_ff3_encrypt, register_employ, HASH_Function
from flask import Flask, render_template, request, send_file
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from flask import Flask, render_template, request, redirect, url_for, flash  # Asegúrate de incluir flash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from PyPDF2 import PdfReader, PdfWriter
import os

app = Flask(__name__)

# Configuración de la aplicación
app.config.from_object(Config)

mysql = MySQL(app)

app = Flask(__name__)


@app.route('/register_employee', methods=['GET', 'POST'])
def register_employee():
    if request.method == 'GET':
        return render_template('register_employee.html')
    
    if request.method == 'POST':
        # Obtener datos del formulario
        nombre = request.form['nombre']
        apellido_paterno = request.form['apellido_paterno']
        apellido_materno = request.form['apellido_materno']
        
        # Crear contraseña provisional
        contraseña_provisional = secrets.token_urlsafe(8)

        # Generar par de llaves ECDSA
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Serializar llaves en formato base64
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Crear nombres de archivo basados en iniciales
        iniciales = f"{nombre[0]}{nombre[1]}{apellido_paterno[0]}{apellido_paterno[1]}{apellido_materno[0]}{apellido_materno[1]}".upper()
        private_key_filename = f"{iniciales}_private.pem"
        public_key_filename = f"{iniciales}_public.pem"
        password_filename = f"{iniciales}_password.txt"

        # Guardar archivos
        with open(private_key_filename, 'wb') as f:
            f.write(private_key_bytes)
        with open(public_key_filename, 'wb') as f:
            f.write(public_key_bytes)
        with open(password_filename, 'w') as f:
            f.write(f"Usuario: {iniciales} Contraseña provisional: {contraseña_provisional}")

        ##HASH de la contraseña
        #pssw_H = HASH_Function (contraseña_provisional)

        # Aquí guardarías los datos en la base de datos
        register_employ (mysql, nombre, apellido_paterno, apellido_materno, iniciales, contraseña_provisional, public_key_bytes)

       # # Devolver archivos para descarga
       # files = [private_key_filename, public_key_filename, password_filename]
       # zip_filename = f"{iniciales}_data.zip"
       # os.system(f"zip -j {zip_filename} {' '.join(files)}")
       # 
       # return send_file(zip_filename, as_attachment=True)

        return redirect(url_for('register_employee'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor()

        # Verificar en la tabla de usuarios
        cursor.execute("SELECT * FROM users WHERE name=%s AND password=%s", (username, password))
        user = cursor.fetchone()

        if user:
            # Inicio de sesión exitoso para usuario
            return f"Bienvenido, {user[1]} (Usuario)"

        # Verificar en la tabla de empleados
        cursor.execute("SELECT * FROM Empleados WHERE usuario=%s AND contraseña=%s", (username, password))
        employee = cursor.fetchone()

        if employee:
            # Inicio de sesión exitoso para empleado
            return f"Bienvenido, {employee[1]} {employee[2]} (Empleado)"

        # Credenciales incorrectas
        return "Usuario o contraseña incorrectos"


# @app.route('/register', methods=['POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    if request.method == 'POST':
        name = request.form['name']
        phone_number = request.form['phone_number']
        card_number = request.form['card_number']
        password = request.form['password']  # Nueva entrada para la contraseña

        cipher_card_number = aes_ff3_encrypt(card_number)

        # Usar la función de modelo para registrar al usuario
        register_user(mysql, name, phone_number, cipher_card_number, password)

        return redirect(url_for('index'))

@app.route('/compras', methods=['GET'])
def mostrar_compras():
    cursor = mysql.connection.cursor()

    # Obtener las compras junto con el nombre del empleado
    query = """
    SELECT c.id, c.descripcion, c.monto, c.fecha, 
           e.nombre, e.apellido_paterno, e.apellido_materno 
    FROM Compras c
    JOIN Empleados e ON c.empleado_id = e.id
    ORDER BY c.fecha DESC
    """
    cursor.execute(query)
    compras = cursor.fetchall()

    # Renderizar la plantilla con los datos
    return render_template('compras.html', compras=compras)

# Ruta para subir y firmar un documento
app.secret_key = 'your_secret_key'  # Necesario para mensajes flash

UPLOAD_FOLDER = 'uploads'
SIGNED_FOLDER = 'signed_docs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)


@app.route('/firmar_documento', methods=['GET', 'POST'])
def sign_document():
    if request.method == 'GET':
        return render_template('firmar_documento.html')

    if request.method == 'POST':
        try:
            # Cargar archivo de clave privada
            private_key_file = request.files.get('private_key')
            if not private_key_file or not private_key_file.filename.endswith('.pem'):
                flash("Por favor, suba un archivo válido de clave privada (.pem).")
                return redirect(request.url)

            private_key_path = os.path.join(UPLOAD_FOLDER, private_key_file.filename)
            private_key_file.save(private_key_path)

            # Leer la clave privada
            with open(private_key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None  # Si la clave tiene contraseña, debe manejarse aquí
                )

            # Cargar archivo PDF
            pdf_file = request.files.get('pdf_file')
            if not pdf_file or not pdf_file.filename.endswith('.pdf'):
                flash("Por favor, suba un archivo válido de documento PDF.")
                return redirect(request.url)

            pdf_path = os.path.join(UPLOAD_FOLDER, pdf_file.filename)
            pdf_file.save(pdf_path)

            # Leer contenido del PDF para firmar
            reader = PdfReader(pdf_path)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)

            # Crear un hash del contenido del PDF
            pdf_data = open(pdf_path, 'rb').read()
            digest = hashes.Hash(hashes.SHA256())
            digest.update(pdf_data)
            hashed_data = digest.finalize()

            # Firmar el hash con ECDSA
            signature = private_key.sign(
                hashed_data,
                ec.ECDSA(hashes.SHA256())
            )

            # Guardar el PDF firmado con la firma adjunta como metadatos
            writer.add_metadata({
                '/Signature': signature.hex()
            })
            signed_pdf_path = os.path.join(SIGNED_FOLDER, f"signed_{pdf_file.filename}")
            with open(signed_pdf_path, 'wb') as signed_pdf:
                writer.write(signed_pdf)

            flash("El documento ha sido firmado exitosamente.")
            return redirect('/firmar_documento')

        except Exception as e:
            flash(f"Ha ocurrido un error: {str(e)}")
            return redirect(request.url)

if __name__ == '__main__':
    app.run(debug=True)
