from flask_mysqldb import MySQL
from ff3 import FF3Cipher
import hashlib

#Configuracion de HASH
mensaje = b"Mensaje secreto"
m = hashlib.sha256()

# Configuración del cifrado
clave_bytes = b'0123456789abcdef'  # Clave de 128 bits (16 bytes)
tweak_bytes = b'20220101'          # Tweak de 7 bytes (56 bits)

# Convierte los bytes a una cadena hexadecimal
clave_hex = clave_bytes.hex()  # Convierte la clave a formato hexadecimal
tweak_hex = tweak_bytes.hex()  # Convierte el tweak a formato hexadecimal

# Inicialización del cifrador FF3-1 con el alfabeto numérico
cifrador = FF3Cipher.withCustomAlphabet(clave_hex, tweak_hex, '0123456789')

def HASH_Function(mensaje):
    m.update(mensaje)
    return m.hexdigest()  

def aes_ff3_encrypt(tarjeta_original):
    # Cifrado de la tarjeta
    tarjeta_cifrada = cifrador.encrypt(tarjeta_original)
    #print("Tarjeta cifrada:", tarjeta_cifrada)
    return tarjeta_cifrada

    ## Descifrado de la tarjeta
    #tarjeta_descifrada = cifrador.decrypt(tarjeta_cifrada)
    #print("Tarjeta descifrada:", tarjeta_descifrada)


def register_user(mysql, name, phone_number, card_number, password):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO users (name, phone_number, card_number, password) VALUES (%s, %s, %s, %s)", 
                (name, phone_number, card_number, password))
    mysql.connection.commit()
    cur.close()
    
def register_employ(mysql, nombre, a_p, a_m, user, password, pub_key):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO Empleados (nombre, apellido_paterno, apellido_materno, usuario, contraseña, llave_publica) VALUES (%s, %s, %s, %s, %s, %s)", 
                (nombre, a_p, a_m, user, password, pub_key))
    mysql.connection.commit()
    cur.close()
