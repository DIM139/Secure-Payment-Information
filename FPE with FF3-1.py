from ff3 import FF3Cipher

# Configuración del cifrado
clave_bytes = b'0123456789abcdef'  # Clave de 128 bits (16 bytes)
tweak_bytes = b'20220101'          # Tweak de 7 bytes (56 bits)

# Convierte los bytes a una cadena hexadecimal
clave_hex = clave_bytes.hex()  # Convierte la clave a formato hexadecimal
tweak_hex = tweak_bytes.hex()  # Convierte el tweak a formato hexadecimal

# Inicialización del cifrador FF3-1 con el alfabeto numérico
cifrador = FF3Cipher.withCustomAlphabet(clave_hex, tweak_hex, '0123456789')

# Número de tarjeta de crédito de ejemplo
tarjeta_original = "40276665778355165"

# Cifrado de la tarjeta
tarjeta_cifrada = cifrador.encrypt(tarjeta_original)
print("Tarjeta cifrada:", tarjeta_cifrada)

# Descifrado de la tarjeta
tarjeta_descifrada = cifrador.decrypt(tarjeta_cifrada)
print("Tarjeta descifrada:", tarjeta_descifrada)
