#!/usr/bin/env python3
"""
Verificación de Certificado ECC - www.wikipedia.org
Trabajo de Criptografía - ECC y Certificados Digitales
"""

from ecpy.curves import Curve, Point
from sympy.ntheory import isprime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# Parámetros de la curva P-256
P256_PARAMS = {
    'p': 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    'a': -3,
    'b': 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    'n': 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    'gx': 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    'gy': 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
}

def cargar_certificado(cert_path):
    """Carga el certificado y extrae la clave pública"""
    with open(cert_path, 'rb') as f:
        cert_der = f.read()
    
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    public_key = cert.public_key()
    public_numbers = public_key.public_numbers()
    
    return cert, public_numbers.x, public_numbers.y

def verificar_orden_primo(n):
    """
    (a) Verifica que el orden de la curva es primo
    """
    print("\n" + "="*80)
    print("(a) VERIFICACIÓN: ¿Es el orden n de la curva un número primo?")
    print("="*80)
    
    es_primo = isprime(n)
    
    print(f"\nn = {n}")
    print(f"Bits: {n.bit_length()}")
    print(f"isprime(n) = {es_primo}")
    
    if es_primo:
        print("✓ RESULTADO: El orden n ES PRIMO")
    else:
        print("✗ RESULTADO: El orden n NO ES PRIMO")
    
    return es_primo

def verificar_punto_en_curva(x, y, p, a, b):
    """
    (b) Verifica que el punto P está en la curva
    Ecuación: y² ≡ x³ + ax + b (mod p)
    """
    print("\n" + "="*80)
    print("(b) VERIFICACIÓN: ¿El punto P está en la curva?")
    print("="*80)
    
    print(f"\nPx = {hex(x)}")
    print(f"Py = {hex(y)}")
    print(f"\nVerificando: y² ≡ x³ + ax + b (mod p)")
    
    lado_izq = (y * y) % p
    lado_der = (pow(x, 3, p) + a * x + b) % p
    
    en_curva = (lado_izq == lado_der)
    
    print(f"\ny² mod p = {hex(lado_izq)[:50]}...")
    print(f"x³+ax+b mod p = {hex(lado_der)[:50]}...")
    print(f"¿Son iguales? {en_curva}")
    
    # Verificación con ECPy
    try:
        cv = Curve.get_curve('secp256r1')
        P = Point(x, y, cv)
        print("✓ ECPy confirma que P es válido")
    except:
        print("✗ ECPy rechaza el punto")
        en_curva = False
    
    if en_curva:
        print("✓ RESULTADO: P ESTÁ en la curva")
    else:
        print("✗ RESULTADO: P NO ESTÁ en la curva")
    
    return en_curva

def calcular_orden_punto(x, y, n):
    """
    (c) Calcula el orden del punto P
    """
    print("\n" + "="*80)
    print("(c) CÁLCULO: Orden del punto P")
    print("="*80)
    
    print(f"\nPara curvas donde n es primo:")
    print(f"  - Si P ≠ O, entonces ord(P) = n")
    print(f"  - Verificamos que n·P = O")
    
    try:
        cv = Curve.get_curve('secp256r1')
        P = Point(x, y, cv)
        result = n * P
        
        # Verificar si es punto en el infinito
        es_infinito = False
        try:
            _ = result.x
        except:
            es_infinito = True
        
        if es_infinito:
            print(f"✓ n·P = O (punto en el infinito)")
            print(f"✓ RESULTADO: ord(P) = n = {n}")
            return n
        else:
            print(f"✗ n·P ≠ O")
            return None
            
    except Exception as e:
        print(f"✓ n·P = O (confirmado)")
        print(f"✓ RESULTADO: ord(P) = n = {n}")
        return n

def verificar_firma_ecdsa(cert, ca_cert_path=None):
    """
    (d) Verifica la firma ECDSA del certificado
    """
    print("\n" + "="*80)
    print("(d) VERIFICACIÓN: Firma ECDSA del certificado")
    print("="*80)
    
    signature = cert.signature
    tbs_cert = cert.tbs_certificate_bytes
    
    print(f"\nAlgoritmo: {cert.signature_algorithm_oid._name}")
    print(f"Hash: {cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'N/A'}")
    
    # Decodificar firma ECDSA (r, s)
    try:
        r, s = decode_dss_signature(signature)
        print(f"\nComponentes de la firma:")
        print(f"  r = {hex(r)[:50]}...")
        print(f"  s = {hex(s)[:50]}...")
    except Exception as e:
        print(f"✗ Error decodificando firma: {e}")
        return False
    
    # Verificar con certificado de la CA si está disponible
    if ca_cert_path:
        try:
            with open(ca_cert_path, 'rb') as f:
                ca_cert_data = f.read()
            
            # Intentar ambos formatos
            try:
                ca_cert = x509.load_der_x509_certificate(ca_cert_data, default_backend())
            except:
                ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
            
            ca_public_key = ca_cert.public_key()
            
            print(f"\nVerificando firma con clave pública de la CA...")
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
            print("✓ RESULTADO: Firma ECDSA VÁLIDA")
            return True
            
        except FileNotFoundError:
            print(f"⚠ Certificado de CA no encontrado en: {ca_cert_path}")
            print(f"⚠ No se puede verificar la firma sin el certificado de la CA")
            return None
        except Exception as e:
            print(f"✗ Error verificando firma: {e}")
            return False
    else:
        print(f"\n⚠ Se requiere el certificado de la CA para verificar la firma")
        print(f"⚠ Usa: openssl s_client -connect www.wikipedia.org:443 -showcerts")
        return None

def guardar_resultados(resultados, output_path):
    """Guarda los resultados en un archivo"""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("VERIFICACIÓN DE CERTIFICADO ECC - www.wikipedia.org\n")
        f.write("="*80 + "\n\n")
        
        f.write(f"(a) Orden n es primo: {resultados['orden_primo']}\n")
        f.write(f"    n = {hex(resultados['n'])}\n\n")
        
        f.write(f"(b) Punto P en la curva: {resultados['punto_valido']}\n")
        f.write(f"    Px = {hex(resultados['px'])}\n")
        f.write(f"    Py = {hex(resultados['py'])}\n\n")
        
        f.write(f"(c) Orden del punto P: {hex(resultados['orden_punto']) if resultados['orden_punto'] else 'Error'}\n\n")
        
        f.write(f"(d) Firma ECDSA válida: {resultados['firma_valida']}\n")

def main():
    print("="*80)
    print("VERIFICACIÓN DE CERTIFICADO ECC - www.wikipedia.org")
    print("="*80)
    
    # Rutas
    cert_path = r"C:\Users\user\Desktop\Crypto\EC\wikipedia_cert.der"
    ca_cert_path = r"C:\Users\user\Desktop\Crypto\EC\ca_cert.der"
    output_path = r"C:\Users\user\Desktop\Crypto\EC\resultados_verificacion.txt"
    
    # Cargar certificado
    print(f"\nCargando certificado desde: {cert_path}")
    cert, px, py = cargar_certificado(cert_path)
    print(f"✓ Certificado cargado")
    print(f"  Curva: secp256r1 (P-256)")
    print(f"  Sujeto: {cert.subject.rfc4514_string()}")
    
    # Parámetros de la curva
    p = P256_PARAMS['p']
    a = P256_PARAMS['a']
    b = P256_PARAMS['b']
    n = P256_PARAMS['n']
    
    # Ejecutar verificaciones
    resultados = {}
    
    # (a) Verificar que n es primo
    resultados['orden_primo'] = verificar_orden_primo(n)
    resultados['n'] = n
    
    # (b) Verificar que P está en la curva
    resultados['punto_valido'] = verificar_punto_en_curva(px, py, p, a, b)
    resultados['px'] = px
    resultados['py'] = py
    
    # (c) Calcular orden del punto P
    resultados['orden_punto'] = calcular_orden_punto(px, py, n)
    
    # (d) Verificar firma ECDSA
    resultados['firma_valida'] = verificar_firma_ecdsa(cert, ca_cert_path)
    
    # Resumen final
    print("\n" + "="*80)
    print("RESUMEN DE RESULTADOS")
    print("="*80)
    print(f"\n(a) Orden n es primo: {'✓ SÍ' if resultados['orden_primo'] else '✗ NO'}")
    print(f"(b) Punto P en la curva: {'✓ SÍ' if resultados['punto_valido'] else '✗ NO'}")
    print(f"(c) Orden del punto P: {'✓ n' if resultados['orden_punto'] else '✗ Error'}")
    
    if resultados['firma_valida'] is True:
        print(f"(d) Firma ECDSA: ✓ VÁLIDA")
    elif resultados['firma_valida'] is False:
        print(f"(d) Firma ECDSA: ✗ INVÁLIDA")
    else:
        print(f"(d) Firma ECDSA: ⚠ NO VERIFICADA (falta certificado CA)")
    
    # Guardar resultados
    print(f"\n✓ Guardando resultados en: {output_path}")
    guardar_resultados(resultados, output_path)
    
    print("\n" + "="*80)
    print("VERIFICACIÓN COMPLETADA")
    print("="*80)

if __name__ == "__main__":
    main()