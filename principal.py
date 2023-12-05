import AES
import ECDH
import ECDSA

# Generar claves de ECDSA
nombre = input("Ingresa como vas a diferenciar el nombre de tu par de llaves: ")
print("\n")
print(f'Tus llaves y tu firma se guardaran con el nombre {nombre}')
clave_privada, clave_publica = ECDSA.generar_par_claves()
ECDSA.guardar_clave_privada_en_archivo(clave_privada, f'clave_privada_{nombre}.pem')
ECDSA.guardar_clave_publica_en_archivo(clave_publica, f'clave_publica_{nombre}.pem')

# Firmar un archivo ECDSA
ruta_documento = input("Ruta del archivo: ")
ruta_clave_privada = input("Ruta de la clave privada: ")
nombre_archivo_firmado = input("Ingresa como vas a diferenciar el nombre de tu archivo firmado: ")
print("\n")
print(f'El archivo a firmar es {ruta_documento}')
print(f'La clave privada a utilizar es {ruta_clave_privada}')
print(f'El archivo firmado se guardara con el nombre {nombre_archivo_firmado}')
print("\n")
clave_privada = ECDSA.cargar_clave_desde_archivo(ruta_clave_privada)
firma = ECDSA.firmar_documento(clave_privada, ruta_documento)
ECDSA.guardar_firma_en_archivo(firma, nombre_archivo_firmado)

# Verificar firma ECDSA
ruta_documento = input("Ruta del archivo: ")
ruta_clave_publica = input("Ruta de la clave pública: ")
ruta_firma = input("Ruta de la firma: ")
print("\n")
print(f'El archivo a verificar es {ruta_documento}')
print(f'La clave pública a utilizar es {ruta_clave_publica}')
print(f'La firma a utilizar es {ruta_firma}')
print("\n")
clave_publica = ECDSA.cargar_clave_publica_desde_archivo(ruta_clave_publica)
firma = ECDSA.cargar_firma_desde_archivo(ruta_firma)
verificacion = ECDSA.verificar_firma(clave_publica, ruta_documento, firma)
if verificacion:
    print("La firma es válida")
else:
    print("La firma no es válida")

# Generar claves de ECDH
nombre = input("Ingresa como vas a diferenciar el nombre de tu par de llaves: ")
print("\n")
print(f'Tus llaves se guardaran con el nombre {nombre}')
clave_privada, clave_publica = ECDH.generar_par_claves()
ECDSA.guardar_clave_privada_en_archivo(clave_privada, f'clave_privada_ECDH{nombre}.pem')
ECDSA.guardar_clave_publica_en_archivo(clave_publica, f'clave_publica_ECDH{nombre}.pem')

# Intercambio de claves ECDH
ruta_clave_privada = input("Ruta de la clave privada tuya: ")
ruta_clave_publica = input("Ruta de la clave pública de tu par: ")
print("\n")
print(f'La clave privada tuya a utilizar es {ruta_clave_privada}')
print(f'La clave pública de tu par a utilizar es {ruta_clave_publica}')
print("\n")
clave_privada = ECDSA.cargar_clave_desde_archivo(ruta_clave_privada)
clave_publica = ECDSA.cargar_clave_publica_desde_archivo(ruta_clave_publica)
shared_key = ECDH.calcular_clave_compartida(clave_privada, clave_publica)
hashed_key = ECDH.longitud_llave_aes(shared_key)
print(f'La clave compartida es: {hashed_key}')

# Cifrado de archivo AES
ruta_archivo_original = input("Ruta del archivo original: ")
ruta_archivo_cifrado = input("Ruta para guardar el archivo cifrado: ")
ruta_clave = hashed_key
print("\n")
print(f'El archivo original es {ruta_archivo_original}')
print(f'El archivo cifrado se guardara con el nombre {ruta_archivo_cifrado}')
print(f'La clave a utilizar es {ruta_clave}')
print("\n")
AES.cifrar_archivo_aes_gcm_base64(ruta_archivo_original, ruta_archivo_cifrado, ruta_clave)

# Descifrado de archivo AES
ruta_archivo_cifrado = input("Ruta del archivo cifrado: ")
ruta_archivo_descifrado = input("Ruta para guardar el archivo descifrado: ")
ruta_clave = hashed_key
print("\n")
print(f'El archivo cifrado es {ruta_archivo_cifrado}')
print(f'El archivo descifrado se guardara con el nombre {ruta_archivo_descifrado}')
print(f'La clave a utilizar es {ruta_clave}')
print("\n")
AES.descifrar_archivo_aes_gcm_base64(ruta_archivo_cifrado, ruta_archivo_descifrado, ruta_clave)




