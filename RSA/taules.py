from RSA_Lab_12 import rsa_key
import random
import time

def benchmark_signatures():
    print("\n==== BENCHMARK RSA: sign (TCR) vs sign_slow ====\n")

    sizes = [512, 1024, 2048, 4096, 8192]
    num_tests = 1024

    print("bits |  tiempo medio TCR (s)  |  tiempo medio lento (s)")
    print("--------------------------------------------------------")

    for bits in sizes:
        print(f"\nGenerando clave de {bits} bits...")
        key = rsa_key(bits_modulo=bits)

        # Mensajes aleatorios
        messages = [random.randint(1, key.modulus - 1) for _ in range(num_tests)]

        # TCR
        t0 = time.time()
        for m in messages:
            key.sign(m)
        t1 = time.time()

        # Lento
        t2 = time.time()
        for m in messages:
            key.sign_slow(m)
        t3 = time.time()

        tcr_time = (t1 - t0) / num_tests
        slow_time = (t3 - t2) / num_tests

        print(f"{bits} | {tcr_time:.8f}           | {slow_time:.8f}")



def benchmark_public_operations():
    print("\n==== BENCHMARK RSA: cifrado y verificación (exponente público) ====\n")

    sizes = [512, 1024, 2048, 4096, 8192]
    num_tests = 1024

    print("bits |  tiempo cifrado (s)  |  tiempo verificación (s)")
    print("------------------------------------------------------")

    for bits in sizes:
        print(f"\nGenerando clave de {bits} bits...")
        key = rsa_key(bits_modulo=bits)

        # Mensajes aleatorios
        messages = [random.randint(1, key.modulus - 1) for _ in range(num_tests)]

        # Primero generamos firmas para tener algo que verificar
        signatures = [key.sign(m) for m in messages]

        # Medir cifrado: c = m^e mod n
        t0 = time.time()
        for m in messages:
            _ = pow(m, key.publicExponent, key.modulus)
        t1 = time.time()

        # Medir verificación: m' = s^e mod n (o key.verify)
        t2 = time.time()
        for i, s in enumerate(signatures):
            _ = pow(s, key.publicExponent, key.modulus)
            # o: key.verify(messages[i], s)
        t3 = time.time()

        enc_time = (t1 - t0) / num_tests
        ver_time = (t3 - t2) / num_tests

        print(f"{bits} | {enc_time:.8f}         | {ver_time:.8f}")





if __name__ == "__main__":
    # Prueba rápida de correcto funcionamiento
    print("==== PRUEBA BÁSICA RSA ====")
    key = rsa_key(bits_modulo=512)
    msg = random.randint(1, key.modulus - 1)
    sig = key.sign(msg)
    print("Verificación básica OK:", key.verify(msg, sig))

    # Benchmarks
    benchmark_signatures()
    benchmark_public_operations()
