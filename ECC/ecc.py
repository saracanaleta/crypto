from ecpy.curves import Curve, Point
from sympy.ntheory import isprime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# Parámetros de la curva P-256
P256 = {
    'p': 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    'a': -3,
    'b': 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    'n': 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
}

def cargar_certificado(cert_path):
    #Carga el certificado y extrae la clave pública
    with open(cert_path, 'rb') as f:
        cert = x509.load_der_x509_certificate(f.read(), default_backend())
    
    public_numbers = cert.public_key().public_numbers()
    return cert, public_numbers.x, public_numbers.y

def verificar_orden_primo(n):
    #(a) Verificar que el orden de la curva es primo

    print("\n" + "="*60)
    print("Apartado (a): Verificar que el orden de la curva es primo")
    print("="*60)

    es_primo = isprime(n)
    print("RESULTADO: El orden es primo" if es_primo else "RESULTADO: El orden no es primo")

def verificar_punto_en_curva(x, y, p, a, b):
    # (b) Verificar que el punto P está en la curva

    print("\n" + "="*60)
    print("Apartado (b): Verificar que el punto P esta en la curva")
    print("="*60)
    
    lado_izq = (y * y) % p
    lado_der = (pow(x, 3, p) + a * x + b) % p
    verificacion_manual = (lado_izq == lado_der)
    
    print(f"Verificacion manual: {verificacion_manual}")
    
    verificacion_ecpy = False
    try:
        cv = Curve.get_curve('secp256r1')
        Point(x, y, cv)
        verificacion_ecpy = True
    except:
        verificacion_ecpy = False
    
    print(f"Verificacion ECPy: {verificacion_ecpy}")
    
    en_curva = verificacion_manual and verificacion_ecpy
    print("RESULTADO: P esta en la curva" if en_curva else "RESULTADO: P no esta en la curva")
    return en_curva


def calcular_orden_punto(x, y, n):
    # (c) Calcular el orden del punto P
    
    print("\n" + "="*60)
    print("Apartado (c): Calcular el orden del punto P")
    print("="*60)

    #Verificar que n·P = O (punto en el infinito)
    cv = Curve.get_curve('secp256r1')
    P = Point(x, y, cv)
    result = n * P
    
    # El punto en el infinito no tiene coordenadas accesibles
    es_infinito = False
    try:
        coordenada_x = result.x
    except:
        es_infinito = True
    
    # Como n es primo, el orden de P solo puede ser 1 o n; como P ≠ O, se descarta 1 y el orden es n
    if es_infinito:
        print(f"El orden de P es n: {n}")
    else:
        print(f"Error: n·P ≠ O, el orden no es n")

def verificar_firma_ecdsa(cert, ca_cert_path):
    # (d) Verificar la firma ECDSA del certificado

    print("\n" + "="*60)
    print("Apartado (d): Verificacion de la firma ECDSA")
    print("="*60)

    try:
        with open(ca_cert_path, 'rb') as f:
            ca_cert_data = f.read()

        #Leer certificado CA
        ca_cert = x509.load_der_x509_certificate(ca_cert_data, default_backend())

        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm)
        )

        print("RESULTADO: Firma ECDSA valida")
        return True

    except Exception:
        print("RESULTADO: Firma ECDSA NO valida")
        return False


def main():
    cert_path = r"C:\Users\user\Desktop\Crypto\EC\wikipedia_cert.der"
    ca_cert_path = r"C:\Users\user\Desktop\Crypto\EC\ca_cert.der"
    
    # Cargar certificado
    print(f"Cargando certificado...")
    cert, px, py = cargar_certificado(cert_path)
    print(f"Certificado cargado: {cert.subject.rfc4514_string()}")
    
    #Apartados
    verificar_orden_primo(P256['n'])
    verificar_punto_en_curva(px, py, P256['p'], P256['a'], P256['b'])
    calcular_orden_punto(px, py, P256['n'])
    verificar_firma_ecdsa(cert, ca_cert_path)
    

if __name__ == "__main__":
    main()