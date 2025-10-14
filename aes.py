# -*- coding: utf-8 -*-
from gf import G_F

class AES:
    """
    Documento de referencia:
    Federal Information Processing Standards Publication (FIPS) 197: Advanced Encryption
    Standard (AES) https://doi.org/10.6028/NIST.FIPS.197-upd1
    El nombre de los métodos, tablas, etc son los mismos (salvo capitalización)
    que los empleados en el FIPS 197
    """
    def __init__(self, key, Polinomio_Irreducible = 0x11B):
        """
        Entrada:
            key: bytearray de 16 24 o 32 bytes
            Polinomio_Irreducible: Entero que representa el polinomio para construir el cuerpo
        SBox: equivalente a la tabla 4, pág. 14
        InvSBOX: equivalente a la tabla 6, pág. 23
        Rcon: equivalente a la tabla 5, pág. 17
        InvMixMatrix : equivalente a la matriz usada en 5.3.3, pág. 24
        """

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key debe ser bytes o bytearray")
        if len(key) not in (16, 24, 32):
            raise ValueError("key debe tener 16, 24 o 32 bytes")

        self.key = bytearray(key)
        self.Nb = 4
        # key length
        self.Nk = len(self.key)
        # number of rounds
        self.Nr = {4:10, 6:12, 8:14}[self.Nk]

        self.Polinomio_Irreducible = Polinomio_Irreducible

        self._gf = G_F(self.Polinomio_Irreducible)

        self.SBox = self._build_sbox()
        self.InvSBox = self._build_invsbox(self.SBox)
        self.Rcon = self._build_rcon(self.Nr)
        self.InvMixMatrix = None

    def _build_sbox(self):
        
        s = [0]*256
        for x in range(256):
            # finds the multiplicative invers in GF
            inv = self._gf.inverso(x) if x != 0 else 0
            # affine transformation
            s[x] = self._affine(inv)
        return s
    
    def _affine(self, b):

        # bi′​=bi​⊕b(i+4)​⊕b(i+5)​⊕b(i+6)​⊕b(i+7)​⊕ci with c=0x63
        t = b ^ self._rotl8(b,1) ^ self._rotl8(b,2) ^ self._rotl8(b,3) ^ self._rotl8(b,4)
        return (t ^ 0x63) & 0xFF

    def _build_invsbox(self, sbox):

        # equivalent to applying the inverse affine transformation and multiplicative inversion in GF(2⁸)
        inv = [0]*256
        for a in range(256):
            inv[sbox[a]] = a
        return inv

    def _build_rcon(self, rounds):

        # Rcon[i] = [x^(i−1), {00}, {00}, {00}], where x^(i−1) is computed in GF(2⁸)
        r = [0x00]*(rounds+1)
        r[1] = 0x01
        for i in range(2, rounds+1):
            r[i] = self._gf.xTimes(r[i-1])
        return r

    @staticmethod
    def _rotl8(x, s):

        # circular rotation to the left, keeping only the lower 8 bits
        return ((x << s) | (x >> (8 - s))) & 0xFF

    def SubBytes(self, State):
        """
        5.1.1 SUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        """

        if not isinstance(State, (bytes, bytearray)) or len(State) != 16:
            raise ValueError("State must be a bytes/bytearray of 16 bytes")
        
        # every b in State is replaced with Sbox[b]
        return bytearray(self.SBox[b] for b in State)

    def InvSubBytes(self, State):
        """
        5.3.2 INVSUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        """

        if not isinstance(State, (bytes, bytearray)) or len(State) != 16:
            raise ValueError("State must be a bytes/bytearray of 16 bytes")
        
        # every b in State is replaced with InvSbox[b]
        return bytearray(self.InvSBox[b] for b in State)

    def ShiftRows(self, State):
        """
        5.1.2 SHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        """

        if not isinstance(State, (bytes, bytearray)) or len(State) != 16:
            raise ValueError("State must be a bytes/bytearray of 16 bytes")

        s = list(State)
        # shifts row 1 - 1 byte to the left
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        # shifts row 2 - 2 bytes to the left
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        # shifts row 3 - 3 bytes to the left
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        return bytearray(s)

    def InvShiftRows(self, State):
        """
        5.3.1 INVSHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        """

        if not isinstance(State, (bytes, bytearray)) or len(State) != 16:
            raise ValueError("State must be a bytes/bytearray of 16 bytes")

        s = list(State)
        # shifts row 1 - 1 byte to the right
        s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
        # shifts row 2 - 2 bytes to the right
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        # shifts row 3 - 3 bytes to the right
        s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]
        return bytearray(s)

    def MixColumns(self, State):
        """
        5.1.3 MIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        """

        if not isinstance(State, (bytes, bytearray)) or len(State) != 16:
            raise ValueError("State must be a bytes/bytearray of 16 bytes")

        s = list(State)
        gf = self._gf

        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = s[i:i+4]

            # first row = 2*a0 ⊕ 3*a1 ⊕ 1*a2 ⊕ 1*a3
            s[i+0] = gf.producto(0x02, a0) ^ gf.producto(0x03, a1) ^ a2 ^ a3
            # second row = 1*a0 ⊕ 2*a1 ⊕ 3*a2 ⊕ 1*a3
            s[i+1] = a0 ^ gf.producto(0x02, a1) ^ gf.producto(0x03, a2) ^ a3
            # third row = 1*a0 ⊕ 1*a1 ⊕ 2*a2 ⊕ 3*a3
            s[i+2] = a0 ^ a1 ^ gf.producto(0x02, a2) ^ gf.producto(0x03, a3)
            # forth row = 3*a0 ⊕ 1*a1 ⊕ 1*a2 ⊕ 2*a3
            s[i+3] = gf.producto(0x03, a0) ^ a1 ^ a2 ^ gf.producto(0x02, a3)

        return bytearray(s)

    def InvMixColumns(self, State):
        """
        5.3.3 INVMIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        """

        if not isinstance(State, (bytes, bytearray)) or len(State) != 16:
            raise ValueError("State must be a bytes/bytearray of 16 bytes")

        s = list(State)
        gf = self._gf

        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = s[i:i+4]

            # first row = 0E*a0 ⊕ 0B*a1 ⊕ 0D*a2 ⊕ 09*a3
            s[i+0] = (gf.producto(0x0E, a0) ^
                      gf.producto(0x0B, a1) ^
                      gf.producto(0x0D, a2) ^
                      gf.producto(0x09, a3))
            # second row = 09*a0 ⊕ 0E*a1 ⊕ 0B*a2 ⊕ 0D*a3
            s[i+1] = (gf.producto(0x09, a0) ^
                      gf.producto(0x0E, a1) ^
                      gf.producto(0x0B, a2) ^
                      gf.producto(0x0D, a3))
            # third row = 0D*a0 ⊕ 09*a1 ⊕ 0E*a2 ⊕ 0B*a3
            s[i+2] = (gf.producto(0x0D, a0) ^
                      gf.producto(0x09, a1) ^
                      gf.producto(0x0E, a2) ^
                      gf.producto(0x0B, a3))
            # forth row = 0B*a0 ⊕ 0D*a1 ⊕ 09*a2 ⊕ 0E*a3
            s[i+3] = (gf.producto(0x0B, a0) ^
                      gf.producto(0x0D, a1) ^
                      gf.producto(0x09, a2) ^
                      gf.producto(0x0E, a3))

        return bytearray(s)

    def AddRoundKey(self, State, roundKey):
        """
        5.1.4 ADDROUNDKEY()
        FIPS 197: Advanced Encryption Standard (AES)
        """

        if not (isinstance(State, (bytes, bytearray)) and len(State) == 16):
            raise ValueError("State must be a bytes/bytearray of 16 bytes")
        
        if not (isinstance(roundKey, (bytes, bytearray)) and len(roundKey) == 16):
            raise ValueError("roundKey must be a bytes/bytearray of 16 bytes")

        # XOR element by element between State and roundKey
        return bytearray([State[i] ^ roundKey[i] for i in range(16)])

    def KeyExpansion(self, key):
        """
        5.2 KEYEXPANSION()
        FIPS 197: Advanced Encryption Standard (AES)
        """

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes or bytearray")
        
        if len(key) not in (16, 24, 32):
            raise ValueError("key must be 16, 24 or 32 bytes")

        Nk = len(key) // 4
        Nr = {4:10, 6:12, 8:14}[Nk]
        Nb = 4

        W = [list(key[4*i:4*(i+1)]) for i in range(Nk)]

        # returns [a₁, a₂, a₃, a₀]
        def RotWord(word):
            return word[1:] + word[:1]

        # returns [SBOX(a₀), SBOX(a₁), SBOX(a₂), SBOX(a₃)]
        def SubWord(word):
            return [self.SBox[b] for b in word]

        for i in range(Nk, Nb*(Nr+1)):
            temp = W[i-1].copy()
            if i % Nk == 0:
                temp = SubWord(RotWord(temp))
                temp[0] ^= self.Rcon[i//Nk]
            elif Nk > 6 and i % Nk == 4:
                temp = SubWord(temp)

            # w[i] = w[i−Nk] xor temp
            W.append([W[i-Nk][j] ^ temp[j] for j in range(4)])

        expanded_key = bytearray(sum(W, []))
        return expanded_key

    def Cipher(self, State, Nr, Expanded_KEY):
        """
        5.1 Cipher(), Algorithm 1 pág. 12
        FIPS 197: Advanced Encryption Standard (AES)
        """

        if not isinstance(State, (bytes, bytearray)) or len(State) != 16:
            raise ValueError("State must be 16 bytes")

        # w[4*i .. 4*i+3]
        RoundKeys = [Expanded_KEY[16*i:16*(i+1)] for i in range(Nr+1)]

        State = self.AddRoundKey(State, RoundKeys[0])

        # round 1 to Nr-1
        for rnd in range(1, Nr):
            State = self.SubBytes(State)
            State = self.ShiftRows(State)
            State = self.MixColumns(State)
            State = self.AddRoundKey(State, RoundKeys[rnd])

        # last round without MixColumns
        State = self.SubBytes(State)
        State = self.ShiftRows(State)
        State = self.AddRoundKey(State, RoundKeys[Nr])

        return State

    def InvCipher(self, State, Nr, Expanded_KEY):
        """
        5. InvCipher()
        Algorithm 3 pág. 20 o Algorithm 4 pág. 25. Son equivalentes
        FIPS 197: Advanced Encryption Standard (AES)
        """

        if not isinstance(State, (bytes, bytearray)) or len(State) != 16:
            raise ValueError("State must be 16 bytes")

        # w[4*Nr .. 4*Nr+3]
        RoundKeys = [Expanded_KEY[16*i:16*(i+1)] for i in range(Nr+1)]

        State = self.AddRoundKey(State, RoundKeys[Nr])

        # round Nr-1 down to 1
        for rnd in range(Nr-1, 0, -1):
            State = self.InvShiftRows(State)
            State = self.InvSubBytes(State)
            State = self.AddRoundKey(State, RoundKeys[rnd])
            State = self.InvMixColumns(State)

        # last round without InvMixColumns
        State = self.InvShiftRows(State)
        State = self.InvSubBytes(State)
        State = self.AddRoundKey(State, RoundKeys[0])

        return State
    
    def encrypt_file(self, fichero):
        """
        Entrada: Nombre del fichero a cifrar
        Salida: Fichero cifrado usando la clave utilizada en el constructor de la clase.
            Para cifrar se usará el modo CBC, con IV correspondiente a los 16
            primeros bytes obtenidos al aplicar el sha256 a la concatenación
            de "IV" y la clave usada para cifrar. Por ejemplo:
                Key 0x0aba289662caa5caaa0d073bd0b575f4
                     IV asociado 0xeb53bf26511a8c0b67657ccfec7a25ee
                Key 0x46abd80bdcf88518b2bec4b7f9dee187b8c90450696d2b995f26cdf2fe058610
                    IV asociado 0x4fe68dfd67d8d269db4ad2ebac646986
            El padding usado será PKCS7.
            El nombre de fichero cifrado será el obtenido al añadir el sufijo .enc
            al nombre del fichero a cifrar: NombreFichero --> NombreFichero.enc
        """

        import hashlib
        from hashlib import sha256

        IV = bytearray(sha256(b"IV" + bytes(self.key)).digest()[:16])

        with open(fichero, "rb") as f:
            data = f.read()

        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len]) * pad_len

        expanded = self.KeyExpansion(self.key)

        prev = IV
        out = bytearray()
        for i in range(0, len(data), 16):
            block = bytearray(data[i:i+16])
            for j in range(16):
                block[j] ^= prev[j]
            cipher_block = self.Cipher(block, self.Nr, expanded)
            out.extend(cipher_block)
            prev = cipher_block

        out_name = fichero + ".enc"
        with open(out_name, "wb") as f:
            f.write(out)

        return out_name


    def decrypt_file(self, fichero):
        """
        Entrada: Nombre del fichero a descifrar
        Salida: Fichero descifrado usando la clave utilizada en el constructor de la clase.
            Para descifrar se usará el modo CBC, con el IV usado para cifrar.
            El nombre de fichero descifrado será el obtenido al añadir el sufijo .dec
            al nombre del fichero a descifrar: NombreFichero --> NombreFichero.dec
        """

        from hashlib import sha256

        with open(fichero, "rb") as f:
            C = f.read()

        if len(C) == 0 or len(C) % 16 != 0:
            raise ValueError("Fichero cifrado inválido (longitud no múltiplo de 16)")

        IV = bytearray(sha256(b"IV" + bytes(self.key)).digest()[:16])

        expanded = self.KeyExpansion(self.key)

        prev = IV
        P = bytearray()
        for i in range(0, len(C), 16):
            Ci = bytearray(C[i:i+16])
            Pi = self.InvCipher(Ci, self.Nr, expanded)
            for j in range(16):
                Pi[j] ^= prev[j]
            P.extend(Pi)
            prev = Ci

        pad = P[-1]
        if pad < 1 or pad > 16 or any(b != pad for b in P[-pad:]):
            raise ValueError("Padding PKCS7 invalid")
        P = P[:-pad]

        out_name = fichero + ".dec"
        with open(out_name, "wb") as f:
            f.write(P)

        return out_name
