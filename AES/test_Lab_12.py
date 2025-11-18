# -*- coding: utf-8 -*-
import argparse
from aes_Lab_12 import G_F, AES

def parse_args():
    parser = argparse.ArgumentParser(
        description="AES en modo CBC con polinomio personalizable (trabajo FIB)"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--cifrar", action="store_true", help="Cifrar fichero")
    group.add_argument("-d", "--descifrar", action="store_true", help="Descifrar fichero")

    parser.add_argument("-f", "--fichero", required=True, help="Ruta del fichero a procesar")
    parser.add_argument("-p", "--polinomio", required=False, default="0x11B",
                        help="Polinomio irreducible en hexadecimal (por defecto 0x11B)")
    parser.add_argument("-k", "--clave", required=True,
                        help="Clave en hexadecimal (16, 24 o 32 bytes)")

    return parser.parse_args()


def hex_to_bytes(hex_str):
    hex_str = hex_str.lower().replace("0x", "")
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str
    return bytes.fromhex(hex_str)


def main():
    args = parse_args()

    key_bytes = hex_to_bytes(args.clave)
    poly = int(args.polinomio, 16)
    aes = AES(bytearray(key_bytes), poly)

    if args.cifrar:
        out = aes.encrypt_file(args.fichero)
        print(f"Fichero cifrado correctamente → {out}")
    elif args.descifrar:
        out = aes.decrypt_file(args.fichero)
        print(f"Fichero descifrado correctamente → {out}")


if __name__ == "__main__":
    main()
