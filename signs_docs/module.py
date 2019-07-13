#!/usr/bin/env python3

import datetime

# le module necessaire pour la cle
from Crypto.PublicKey import RSA


# importations des modules neccessaires pour le certificat
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa



# Genere une paire de clé, la taille de clé par défaut est 2048
def generate_keys(bits=2048):

    key  = RSA.generate(bits)
    # Stocke la clé privé dans une variable
    private_key = key.exportKey()

    # Stocke la clé public dans une variable
    public_key = key.publickey().exportKey()

    # Copie la clé privé dans un fichier

    return public_key, private_key

def generate_keys_rsa(bits=2048,mypass=b'password'):

    # Generation de nos clés
    key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
    )
    pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(mypass)
    )
    public_key = key.public_key()
    pupem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pupem, pem, key
    

def generate_certificat_auto_sign(key, contry_name, city_name, locality_name, organi_name, common_name, nom_domaine):
   
    
   
    # Generation de CSR(Certificate Signing Request)
    # Divers détails sur qui nous sommes. Pour un certificat auto-signé, le sujet et l'émetteur sont toujours les mêmes
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,  contry_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, city_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organi_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
            subject
    ).issuer_name(
            issuer
    ).public_key(
            key.public_key()
    ).serial_number(
            x509.random_serial_number()
    ).not_valid_before(
            datetime.datetime.utcnow()
    ).not_valid_after(
            # notre certificate sera valide pour 10 jours
            datetime.datetime.utcnow() + datetime.timedelta(days=30)
    ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(nom_domaine)]),
            critical=False,
    # Signer notre certificat avec notre clé privé
    ).sign(key, hashes.SHA256(), default_backend())


    certif = cert.public_bytes(serialization.Encoding.PEM)

    return certif



