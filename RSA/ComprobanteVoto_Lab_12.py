import base64
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def limpiar_codi(Codi):
    # Limpiar el cóodi
    Codi_limpio = Codi.replace(" ", "").replace("\n", "").replace("\r", "")
    
    # Dividir el ccodi
    try:
        partes = Codi_limpio.split("#")
        if len(partes) != 5:
            return None
        
        firma_b64 = partes[0]
        ballot_id_b64 = partes[1]
        election_id = partes[2]
        election_event_id = partes[3]
        timestamp = partes[4]
        
        return (firma_b64, ballot_id_b64, election_id, election_event_id, timestamp)
    except:
        return None


def validar_firma(firma_b64, ballot_id_b64, election_id, election_event_id, timestamp, Certificado):
    try:
        ballot_id = base64.b64decode(ballot_id_b64)
    
        #Dos hash del ballot id
        hash1 = hashlib.sha256(ballot_id).digest()
        hash2 = hashlib.sha256(hash1).digest()
        vote_info = base64.b64encode(hash2).decode('ascii')
        
        signed_data = f"{vote_info};{election_id};{election_event_id};{timestamp}"
        
        #Deodificar firma
        firma = base64.b64decode(firma_b64)
        
        #Coger clave del certificado
        with open(Certificado, 'rb') as f:
            cert_data = f.read()
        
        certificado = x509.load_pem_x509_certificate(cert_data, default_backend())
        public_key = certificado.public_key()
        
        #Verificar firma
        public_key.verify(
            firma,
            signed_data.encode('ascii'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False


def validar_rebut(Rebut, ballot_id_b64):
    try:
        #Decodificar Ballot id
        ballot_id = base64.b64decode(ballot_id_b64)
        hash_ballot = hashlib.sha256(ballot_id).digest()
        
        rebut_reproducido = base64.b64encode(hash_ballot).decode('ascii')
        
        #Comparar Rebut
        if rebut_reproducido[:len(Rebut)] == Rebut:
            return True
        else:
            return False
    except:
        return False


def comprobante_voto(Rebut, Codi, Certificado):
    """
    Entrada: 
        Rebut: String de longitud 10
        Codi: String formado por la concatenación de 5 partes usando # como separador,
              podría contener espacios y saltos de líneas que deben ser eliminados.
        Certificado: Fichero que contiene el certificado, en formato PEM, 
                     con la clave pública del firmante del comprobante de votación.
    
    Salida: 
        0 si el Rebut y la firma del Codi son correctos
        1 si el Rebut es incorrecto pero la firma del Codi es correcta
        2 si el Rebut es correcto pero la firma del Codi es incorrecta
        3 si ni el Rebut ni la firma del Codi son correctos
    """
    
    partes = limpiar_codi(Codi)
    if partes is None:
        return 3
    
    firma_b64, ballot_id_b64, election_id, election_event_id, timestamp = partes
    firma_correcta = validar_firma(firma_b64, ballot_id_b64, election_id, election_event_id, timestamp, Certificado)
    rebut_correcto = validar_rebut(Rebut, ballot_id_b64)
    
    if rebut_correcto and firma_correcta:
        return 0
    elif not rebut_correcto and firma_correcta:
        return 1
    elif rebut_correcto and not firma_correcta:
        return 2
    else:
        return 3

if __name__ == "__main__":
    rebut_ejemplo = "iVoIkFePBM"
    
    codi_ejemplo = """AklTUamCVK4urY+1fO0fBtHz7CYt1RE8
0A/xju/qlkKPkj5gUxZ2NNzO7FuU1a1
dGztjGJvB3oAfLw6rpAMWNgOc+W+pOm
un8vCEiEuAzPWmflr1ACVRBSoC/vioE
DJ8zoVtzJWEv9a+4vmaxRxaZzZoGFiN
7nNscvJXgqU4pvILQO3VWUve6JJ65KV
rAbxRM8bkBshy3yMGjXLVpZDSsKOwjT
YGArsZuX43ITQxbpuitqBujKSw54De1
QDJbv8SGol9aLSMpmZ3O/M1PgjAAf1H
WWjzKlunmzv9LDIoh/nLRU6+3a8CWZ9
L5SfV8/MSHQqfHbXJZd9ZcMBvso4NkA
==#0R0En5w1t0cSTjAbvyOgM/9plEpk
Y3C+#40289dc597e9c1fa0199c2cdf1
29137c#40289dc597e9c1fa0199c2cd
f11c1375#1760076542676"""
    
    certificado_path = "message_server.pem"
    
    resultado = comprobante_voto(rebut_ejemplo, codi_ejemplo, certificado_path)
    
    mensajes = {
        0: "Todo bien",
        1: "Rebut INCORRECTO, firma correcta",
        2: "Rebut correcto, firma INCORRECTA",
        3: "Rebut y firma INCORRECTOS"
    }
    
    print(f"Resultado: {resultado}")
    print(mensajes[resultado])