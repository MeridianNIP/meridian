from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

_ALLOWED_KEY_TYPES = {"rsa2048", "rsa3072", "rsa4096", "ecdsa_p256", "ecdsa_p384", "ed25519"}


@dataclass(frozen=True)
class GeneratedCsr:
    key_type: str
    private_key_pem: bytes  # PKCS8 PEM, no passphrase
    public_key_pem: bytes
    csr_pem: bytes
    subject_cn: str
    sans: list[str]


def generate(
    subject_cn: str,
    sans: list[str],
    *,
    key_type: str = "ecdsa_p256",
    organization: str | None = None,
    country: str | None = None,
) -> GeneratedCsr:
    if key_type not in _ALLOWED_KEY_TYPES:
        raise ValueError(f"key_type must be one of {sorted(_ALLOWED_KEY_TYPES)}")

    # Generate the key.
    if key_type.startswith("rsa"):
        bits = int(key_type[3:])
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        hash_alg: hashes.HashAlgorithm = hashes.SHA256()
    elif key_type == "ecdsa_p256":
        private_key = ec.generate_private_key(ec.SECP256R1())
        hash_alg = hashes.SHA256()
    elif key_type == "ecdsa_p384":
        private_key = ec.generate_private_key(ec.SECP384R1())
        hash_alg = hashes.SHA384()
    else:  # ed25519
        private_key = ed25519.Ed25519PrivateKey.generate()
        hash_alg = None

    # Build the CSR.
    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]
    if organization:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if country:
        name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    subject = x509.Name(name_attrs)

    san_ext_value = x509.SubjectAlternativeName([x509.DNSName(n) for n in (sans or [subject_cn])])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    builder = builder.add_extension(san_ext_value, critical=False)

    # Ed25519 has no concept of external hash algorithm; cryptography expects None.
    csr = builder.sign(private_key, hash_alg)

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

    return GeneratedCsr(
        key_type=key_type,
        private_key_pem=key_pem,
        public_key_pem=pub_pem,
        csr_pem=csr_pem,
        subject_cn=subject_cn,
        sans=list(sans or [subject_cn]),
    )
