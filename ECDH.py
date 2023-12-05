from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def generar_claves_ECDH(curve=ec.SECP224R1()):
    """
    Genera un par de claves (privada y pública) utilizando una curva elíptica dada.
    """
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def calcular_clave_compartida(private_key, peer_public_key):
    """
    Calcula la clave compartida utilizando la clave privada y la clave pública del par.
    """
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key

def longitud_llave_aes(shared_key, length=16):
    """
    Aplica un hash SHA-256 a la clave compartida y la recorta a una longitud específica.
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_key)
    hashed_key = digest.finalize()[:length]
    return hashed_key

# Generar claves para Alicia y Betito
private_key_A, public_key_A = generar_claves_ECDH()
private_key_B, public_key_B = generar_claves_ECDH()

# Calcular las claves compartidas
shared_key_A = calcular_clave_compartida(private_key_A, public_key_B)
shared_key_B = calcular_clave_compartida(private_key_B, public_key_A)

# Hash y recorte de las claves compartidas
hashed_key_A = longitud_llave_aes(shared_key_A)
hashed_key_B = longitud_llave_aes(shared_key_B)

hashed_key_A, hashed_key_B, hashed_key_A == hashed_key_B

