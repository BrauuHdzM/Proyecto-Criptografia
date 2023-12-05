from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import base64

def cifrar_archivo_aes_gcm_base64(archivo_original, archivo_cifrado, clave):
    with open(archivo_original, 'rb') as archivo_in:
        with open(archivo_cifrado, 'wb') as archivo_out:
            iv = secrets.token_bytes(16)
            tag = b''
            cifrador = Cipher(algorithms.AES(clave), modes.GCM(iv, tag=None), backend=default_backend())
            cifrador = cifrador.encryptor()
            
            for bloque in iter(lambda: archivo_in.read(4096), b''):
                bloque_cifrado = cifrador.update(bloque)
            
            # Obtener el tag de autenticación después del cifrado
            tag = cifrador.finalize()
            tag = cifrador.tag

            # Escribir el IV y el tag de autenticación en el archivo cifrado
            archivo_out.write(iv)
            archivo_out.write(tag)
            archivo_out.write(base64.b64encode(bloque_cifrado))

            print("El archivo fue cifrado con éxito")
        
def descifrar_archivo_aes_gcm_base64(archivo_cifrado, archivo_descifrado, clave):
    with open(archivo_cifrado, 'rb') as archivo_in:
        with open(archivo_descifrado, 'wb') as archivo_out:
            iv = archivo_in.read(16)
            tag = archivo_in.read(16)
            
            cifrador = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend())
            cifrador = cifrador.decryptor()
            
            for bloque_codificado in iter(lambda: archivo_in.read(4096), b''):
                bloque = base64.b64decode(bloque_codificado)
                archivo_out.write(cifrador.update(bloque))
            
            # Verificar el tag de autenticación
            try:
                cifrador.finalize()
                # El tag de autenticación es correcto
                print("El tag de autenticación es correcto")
            except Exception as e:
                # El tag de autenticación es incorrecto
                print("Error de autenticación: El archivo podría estar comprometido.")
