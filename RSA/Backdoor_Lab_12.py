import os
import subprocess
import argparse
from math import isqrt
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse

MAX_K = 1000
MAX_EPS = 1000

def load_clave_publica(pem_path):
    with open(pem_path, "rb") as f:
        b = f.read()
    #Obtiene n y e de la clave
    key = RSA.import_key(b)
    n = key.n
    e = key.e
    return n, e


def find_pq(n, e, max_k, max_eps):
    for k in range(1, max_k + 1):
        two_k = 1 << k
        for eps in range(0, max_eps + 1):
            m = e + eps
            if (m & 1) == 0:
                continue
            s = two_k * m
            D = s * s + 4 * n
            t = isqrt(D)
            if t * t == D:
                pq = t
                p = (pq + s) // 2
                q = (pq - s) // 2
                #Comprobar n=p*q
                if p * q == n and p > 1 and q > 1:
                    return int(p), int(q)
    return None, None


def guardar_clave_privada(p, q, e, out_pem="clave_privada_RSA.pem"):
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    n = p * q
    # Construir clave privada PEM
    key = RSA.construct((n, e, d, p, q))
    with open(out_pem, "wb") as f:
        f.write(key.export_key("PEM"))
    print(f"Clave privada guardada en: {out_pem}")
    return out_pem


def descifrar_RSA(private_pem_path, rsa_enc_path, out_path="clave_secreta_AES_descifrada.dec"):
    #Descifrar clave AES con RSA
    cmd = ["openssl", "pkeyutl", "-decrypt", "-inkey", private_pem_path,
           "-in", rsa_enc_path, "-out", out_path]
    res = subprocess.run(cmd, capture_output=True)
    if res.returncode != 0:
        raise RuntimeError("Error openssl")
    print(f"Clave AES recuperada en: {out_path}")
    return out_path


def descifrar_AES(aes_enc_path, recovered_key_path, out_path="AES_descifrado.dec"):
    #Descifrar fichero AES con clave descifrada anteriormente
    cmd = ["openssl", "enc", "-d", "-aes-128-cbc", "-pbkdf2", "-kfile", recovered_key_path,
           "-in", aes_enc_path, "-out", out_path]
    res = subprocess.run(cmd, capture_output=True)
    if res.returncode != 0:
        raise RuntimeError("Error en openssl")
    print(f"Fichero AES descifrado en: {out_path}")
    return out_path


def main():
    #Importante seguir este orden al pasar los argumentos en el comando
    parser = argparse.ArgumentParser(description="RSA Backdoor")
    parser.add_argument("pubkey", help="Archivo de clave pública RSA (.pem)")
    parser.add_argument("rsa_enc", help="Archivo cifrado RSA (.enc)")
    parser.add_argument("aes_enc", help="Archivo cifrado AES (.enc)")
    args = parser.parse_args()

    n, e = load_clave_publica(args.pubkey)

    p, q = find_pq(n, e, max_k=MAX_K, max_eps=MAX_EPS)
    if p is None:
        print("No se encontraron p,q. Aumenta el limite")
        return

    private_pem = guardar_clave_privada(p, q, e)

    recovered_key_path = descifrar_RSA(private_pem, args.rsa_enc)

    try:
        descifrar_AES(args.aes_enc, recovered_key_path)
        print("Todo correcto")
    except Exception as ex:
        print("Error al descifrar AES:", ex)


if __name__ == "__main__":
    main()