#!/usr/bin/python3

import datetime
import enum
import os.path
import sys
import yaml

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048
VALIDITY = datetime.timedelta(days=365*10)

def usage(name):
    print("%s [<cert.yaml>]" % name)


def gen_private_key():
    return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT,
                                    key_size=KEY_SIZE,
                                    backend=default_backend())

class Usage(enum.Enum):
    CLIENT = "client"
    SERVER = "server"


def create_cert(subject_names, ca=False, issuer_key=None, issuer_cert=None,
                usage=None):
    private_key = gen_private_key()

    public_key = private_key.public_key()

    name = \
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_names[0])])

    constraints = x509.BasicConstraints(ca=ca, path_length=None)

    dns_names = [x509.DNSName(subject_name) for subject_name in subject_names]
    alt_name = x509.SubjectAlternativeName(dns_names)

    now = datetime.datetime.utcnow()

    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)

    if issuer_key is not None and issuer_cert is not None:
        sign_key = issuer_key
        issuer = issuer_cert.subject
    else:
        sign_key = private_key
        issuer = name

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .not_valid_before(now)
        .not_valid_after(now + VALIDITY)
        .serial_number(x509.random_serial_number())
        .public_key(public_key)
        .add_extension(constraints, critical=True)
        .add_extension(ski, critical=False)
        .add_extension(alt_name, critical=False)
    )

    if usage is not None:
        l = []
        if Usage.CLIENT in usage:
            l.append(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)
        if Usage.SERVER in usage:
            l.append(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH)

        builder = builder.add_extension(x509.ExtendedKeyUsage(l),
                                        critical=True)

    cert = builder.sign(private_key=sign_key, algorithm=hashes.SHA256(),
                        backend=default_backend())

    return private_key, cert

def get_subject_names(conf):
    if 'subject_name' in conf:
        return [conf['subject_name']]
    else:
        return conf['subject_names']
    

def get_usage(conf):
    server_auth = conf.get('server_auth')
    client_auth = conf.get('client_auth')

    if server_auth is None and client_auth is None:
        return None

    usage = []
    if server_auth:
        usage.append(Usage.SERVER)
    if client_auth:
        usage.append(Usage.CLIENT)

    return usage

def create_certs(conf_certs):
    keys = {}
    certs = {}
    for id, params in conf_certs.items():
        subject_names = get_subject_names(params)
        ca = params.get('ca', False)

        issuer = params.get('issuer')
        if issuer is not None:
            issuer_key = keys[issuer]
            issuer_cert = certs[issuer]
        else:
            issuer_key = None
            issuer_cert = None

        usage = get_usage(params)

        keys[id], certs[id] = \
            create_cert(subject_names, ca, issuer_key, issuer_cert, usage)

    return keys, certs


def assure_dir(file_path):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)


def write_key(key_file, key):
    assure_dir(key_file)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    open(key_file, "wb").write(key_pem)


def write_cert(cert_file, cert):
    assure_dir(cert_file)
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    open(cert_file, "wb").write(cert_pem)


def write_bundle(bundle_file, bundle):
    assure_dir(bundle_file)
    with open(bundle_file, "wb") as f:
        for cert in bundle:
            cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
            f.write(cert_pem)


def get_paths(conf):
    if 'path' in conf:
        return [conf['path']]
    else:
        return conf['paths']


def write_files(base_path, files_conf, keys, certs):
    for file_conf in files_conf:
        type = file_conf['type']
        if type == 'key':
            key = keys[file_conf['id']]
            for path in get_paths(file_conf):
                write_key(os.path.join(base_path, path), key)
        elif type == 'cert':
            cert = certs[file_conf['id']]
            for path in get_paths(file_conf):
                write_cert(os.path.join(base_path, path), cert)
        elif type == 'bundle':
            tc_certs = [certs[cert_id] for cert_id in file_conf['certs']]
            for path in get_paths(file_conf):
                write_bundle(os.path.join(base_path, path), tc_certs)
        elif type == 'ski':
            cert = certs[file_conf['id']]
            ski = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
            ).value.digest
            for path in get_paths(file_conf):
                open(os.path.join(base_path, path), "wb").write(ski)


if len(sys.argv) == 1:
    input = sys.stdin
elif len(sys.argv) == 2:
    input = open(sys.argv[1])
else:
    usage(sys.argv[0])
    sys.exit(1)

conf = yaml.load(sys.stdin, Loader=yaml.Loader)

base_path = conf['base-path']

keys, certs = create_certs(conf['certs'])

write_files(base_path, conf['files'], keys, certs)
