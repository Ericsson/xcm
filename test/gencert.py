#!/usr/bin/python3

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2023 Ericsson AB

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

DEFAULT_VALIDITY_START = datetime.timedelta(0)
DEFAULT_VALIDITY_END = datetime.timedelta(days=365*10)

DEFAULT_CRL_LAST_UPDATE = datetime.timedelta(0)
DEFAULT_CRL_NEXT_UPDATE = datetime.timedelta(days=365*10)

def usage(name):
    print("%s [<cert.yaml>]" % name)


def gen_private_key():
    return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT,
                                    key_size=KEY_SIZE,
                                    backend=default_backend())

class Usage(enum.Enum):
    CLIENT = "client"
    SERVER = "server"

now = datetime.datetime.utcnow()

def create_cert(subject_names, ca, issuer_key, issuer_cert, usage, validity):
    private_key = gen_private_key()

    public_key = private_key.public_key()

    name = \
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_names[0])])

    constraints = x509.BasicConstraints(ca=ca, path_length=None)

    dns_names = [x509.DNSName(subject_name) for subject_name in subject_names]
    alt_name = x509.SubjectAlternativeName(dns_names)

    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)

    if issuer_key is not None and issuer_cert is not None:
        sign_key = issuer_key
        issuer = issuer_cert.subject
    else:
        sign_key = private_key
        issuer = name

    not_valid_before = now + validity[0]
    not_valid_after = now + validity[1]

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
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

    if issuer_cert is not None:
        issuer_ski = issuer_cert.extensions.\
            get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = x509.AuthorityKeyIdentifier.\
            from_issuer_subject_key_identifier(issuer_ski.value)
        builder = builder.add_extension(aki, critical=False)
    else:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)
        builder = builder.add_extension(aki, critical=False)

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

def get_validity(conf):
    validity = conf.get('validity')

    if validity is None:
        return DEFAULT_VALIDITY_START, DEFAULT_VALIDITY_END

    validity_start = datetime.timedelta(seconds=validity[0])
    validity_end = datetime.timedelta(seconds=validity[1])

    return validity_start, validity_end

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

        validity = get_validity(params)

        usage = get_usage(params)

        keys[id], certs[id] = \
            create_cert(subject_names, ca, issuer_key, issuer_cert, usage,
                        validity)

    return keys, certs

def create_crl(issuer_cert, issuer_key, last_update, next_update,
               revoked_certs):
    crl_builder = (
        x509.CertificateRevocationListBuilder()
        .last_update(last_update)
        .next_update(next_update)
        .issuer_name(issuer_cert.issuer)
    )

    revocation_date = last_update

    for revoked_cert in revoked_certs:
        revoked_cert_entry_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(revoked_cert.serial_number)
            .revocation_date(revocation_date)
        )
        revoked_cert_entry = revoked_cert_entry_builder.build(default_backend())

        crl_builder = crl_builder.add_revoked_certificate(revoked_cert_entry)

    crl = crl_builder.sign(private_key=issuer_key, algorithm=hashes.SHA256(),
                           backend=default_backend())
    return crl

def get_abs_time(conf, name, default):
    delta_s = conf.get(name)

    if delta_s is not None:
        return now + datetime.timedelta(seconds=delta_s)
    else:
        return now + default

def create_crls(conf_crls, keys, certs):
    crls = {}
    for crl_id, params in conf_crls.items():
        issuer_id = params['issuer']
        issuer_cert = certs[issuer_id]
        issuer_key = keys[issuer_id]

        last_update = get_abs_time(params, 'last_update',
                                   DEFAULT_CRL_LAST_UPDATE)
        next_update = get_abs_time(params, 'next_update',
                                   DEFAULT_CRL_NEXT_UPDATE)

        revoked_certs = [certs[cert_id] for cert_id in params['revokes']]

        crls[crl_id] = create_crl(issuer_cert, issuer_key, last_update,
                                  next_update, revoked_certs)

    return crls

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


def write_files(base_path, files_conf, keys, certs, crls):
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
        elif type == 'crl':
            crl = crls[file_conf['id']]
            for path in get_paths(file_conf):
                write_cert(os.path.join(base_path, path), crl)
        elif type == 'ski':
            cert = certs[file_conf['id']]
            ski = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
            ).value.digest
            for path in get_paths(file_conf):
                open(os.path.join(base_path, path), "wb").write(ski)


if len(sys.argv) == 1:
    input = sys.stdin
elif len(sys.argv) == 2 and sys.argv[1] != '-h':
    input = open(sys.argv[1])
else:
    usage(sys.argv[0])
    sys.exit(1)

conf = yaml.load(input, Loader=yaml.Loader)

base_path = conf['base-path']

keys, certs = create_certs(conf['certs'])

if 'crls' in conf:
    crls = create_crls(conf['crls'], keys, certs)
else:
    crls = {}

write_files(base_path, conf['files'], keys, certs, crls)
