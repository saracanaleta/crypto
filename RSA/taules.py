import random

def extended_gcd(a, b):
    """
    Extensión algoritmo Eucliedes
    """
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = extended_gcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    """
    Inverso modular: a^{-1} mod m
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception("error inverso modular")
    return x % m

def prime(n, k=40):
    """
    Test de primalidad Miller–Rabin
    """
    if n in (2, 3):
        return True
    if n < 2:
        return False

    # Casos pequeños
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    # Descomponer n−1 = 2^r · d
    r = 0
    d = n - 1

    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """
    Generador de primos de "bits" bits
    """
    while True:
        candidate = random.getrandbits(bits)
        # asegurar tamaño
        candidate |= (1 << (bits - 1))
        # asegurar impar
        candidate |= 1
        if prime(candidate):
            return candidate

class rsa_key:
    def __init__(self,bits_modulo=2048,e=2**16+1):
        """
        genera una clave RSA (de 2048 bits y exponente público 2**16+1 por defecto)
        """
        # Exponente público
        self.publicExponent = e

        # Primos p y q
        bp = bits_modulo // 2
        bq = bits_modulo - bp   # por si bits_modulo es impar
        p = generate_prime(bp)
        q = generate_prime(bq)

        self.primeP = p
        self.primeQ = q

        self.modulus = p * q
        phin = (p - 1) * (q - 1)

        # Exponente privado d
        d = modinv(e, phin)
        self.privateExponent = d

        # Parámetros CRT
        self.privateExponentModulusPhiP = d % (p - 1)
        self.privateExponentModulusPhiQ = d % (q - 1)
        self.inverseQModulusP = modinv(q, p)

    def sign(self, message):
        """
        Entrada: un entero "message"
        Salida: un entero que es la firma de "message" hecha con la clave RSA usando el TCR
        """
        p = self.primeP
        q = self.primeQ

        # mp = m mod p
        mp = message % p
        # mq = m mod q
        mq = message % q

        # Elevar con exponentes reducidos
        sp = pow(mp, self.privateExponentModulusPhiP, p)
        sq = pow(mq, self.privateExponentModulusPhiQ, q)

        # CRT
        h = (self.inverseQModulusP * (sp - sq)) % p
        signature = sq + h * q

        return signature

    def sign_slow(self, message):
        """
        Entrada: un entero "message"
        Salida: un entero que es la firma de "message" hecha con la clave RSA sin usar el TCR
        """
        # s = md mod n
        return pow(message, self.privateExponent, self.modulus)

    def verify(self, message, signature):
        """
        Entrada: dos enteros "message" y "signature"
        Salida: el booleano True si "signature" se corresponde con la firma de "message"
        hecha con la clave RSA;
        el booleano False en cualquier otro caso.
        """
        # m'= signature^e mod n
        mv = pow(signature, self.publicExponent, self.modulus)
        return mv == message

    def __repr__(self):
        return str(self.__dict__)

    def from_dictionary(self, RSAKey):
        """
        Importa una clave RSA:
        RSAKey = {
        'publicExponent': 65537,
        'modulus': 570131475606908079645289541584935910730810198868796008957155625353952799'privateExponent': 4753342970712949550913014106871064919409107720248258835378333364'primeP': 6984543319619713760180514011748821810865467260539703382978371694181772714'primeQ': 8162759532257435135158099414290415000169780797669900784827582678722199767'privateExponentModulusPhiP': 45804459669184686161831989824214201536412548238511972'privateExponentModulusPhiQ': 23195305059619789511581135143862306567002125180433428'inverseQModulusP': 567233782337109666186598736353187660521719314613992812595580843}
        """
        self.publicExponent = RSAKey['publicExponent']
        self.privateExponent = RSAKey['privateExponent']
        self.modulus = RSAKey['modulus']
        self.primeP = RSAKey['primeP']
        self.primeQ = RSAKey['primeQ']
        self.privateExponentModulusPhiP = RSAKey['privateExponentModulusPhiP']
        self.privateExponentModulusPhiQ = RSAKey['privateExponentModulusPhiQ']
        self.inverseQModulusP = RSAKey['inverseQModulusP']



import time

def benchmark_signatures():
    print("\n==== BENCHMARK RSA: sign (TCR) vs sign_slow ====\n")

    sizes = [512, 1024, 2048]  # añade 4096 y 8192 si quieres (ojo tiempo)
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

    sizes = [512, 1024, 2048]  # igual que antes, puedes ampliar
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
