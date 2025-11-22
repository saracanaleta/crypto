import random

def extended_gcd(a, b):
    """
    Extensión algoritmo Eucliedes iterativo
    """
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    
    while b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1

    return a, x0, y0

def modinv(a, m):
    """
    Inverso modular: a^{-1} mod m
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception("error inverso modular")
    return x % m

# Lista de primos pequeños para cribado rápido
_small_primes = [
    3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,
    67,71,73,79,83,89,97,101,103,107,109,113,127,131,
    137,139,149,151,157,163,167,173,179,181,191,193,
    197,199,211,223,227,229,233,239,241,251,257,263,
    269,271,277,281,283,293
]

def probably_prime(n):
    """
    Test de primalidad Miller–Rabin optimitzado
    """
    if n < 2:
        return False

    # Casos pequeños
    for p in _small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Descomponer n−1 = 2^r · d
    r = 0
    d = n - 1

    while d % 2 == 0:
        r += 1
        d //= 2

    # Elegimos número de bases según tamaño
    bits = n.bit_length()
    if bits >= 8192:
        num_bases = 4
    elif bits >= 4096:
        num_bases = 5
    else:
        num_bases = 8  # más pequeño → más tests, más seguridad

    # Usamos bases pseudoaleatorias (distintas cada vez)
    import secrets
    for _ in range(num_bases):
        a = secrets.randbelow(n - 3) + 2  # en [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False

    return True

def generate_prime(bits):
    """
    Generador de primos de "bits" bits optimizado
    """
    import secrets

    while True:
        candidate = secrets.randbits(bits)
        # asegurar el bit más alto
        candidate |= (1 << bits-1)
        # asegurar impar
        candidate |= 1

        if probably_prime(candidate):
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
        bq = bits_modulo - bp
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