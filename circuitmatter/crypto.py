from . import tlv

import ecdsa
import enum
import hashlib
import hmac
import struct

# Section 3.6

SYMMETRIC_KEY_LENGTH_BITS = 128
SYMMETRIC_KEY_LENGTH_BYTES = 16
AEAD_MIC_LENGTH_BITS = 128
AEAD_MIC_LENGTH_BYTES = 16
AEAD_NONCE_LENGTH_BYTES = 13

GROUP_SIZE_BITS = 256
GROUP_SIZE_BYTES = 32
PUBLIC_KEY_SIZE_BYTES = (2 * GROUP_SIZE_BYTES) + 1

HASH_LEN_BITS = 256
HASH_LEN_BYTES = 32
HASH_BLOCK_LEN_BYTES = 64

# Upper limit for encoded certificate size.
CERTIFICATE_SIZE = 400


class DNAttribute(tlv.List):
    # Section 6.5.6.1

    common_name = tlv.UTF8StringMember(1, 100)
    surname = tlv.UTF8StringMember(2, 100)
    serial_num = tlv.UTF8StringMember(3, 100)
    country_name = tlv.UTF8StringMember(4, 100)
    locality_name = tlv.UTF8StringMember(5, 100)
    state_or_province_name = tlv.UTF8StringMember(6, 100)
    org_name = tlv.UTF8StringMember(7, 100)
    org_unit_name = tlv.UTF8StringMember(8, 100)
    title = tlv.UTF8StringMember(9, 100)
    name = tlv.UTF8StringMember(10, 100)
    given_name = tlv.UTF8StringMember(11, 100)
    initials = tlv.UTF8StringMember(12, 100)
    gen_qualifier = tlv.UTF8StringMember(13, 100)
    dn_qualifier = tlv.UTF8StringMember(14, 100)
    pseudonym = tlv.UTF8StringMember(15, 100)
    domain_component = tlv.OctetStringMember(16, 100)
    matter_node_id = tlv.IntMember(17, signed=False, octets=8)
    matter_firmware_signing_id = tlv.IntMember(18, signed=False, octets=8)
    matter_icac_id = tlv.IntMember(19, signed=False, octets=8)
    matter_rcac_id = tlv.IntMember(20, signed=False, octets=8)
    matter_fabric_id = tlv.IntMember(21, signed=False, octets=8)
    matter_noc_cat = tlv.IntMember(22, signed=False, octets=8)
    common_name_ps = tlv.OctetStringMember(129, 100)
    surname_ps = tlv.OctetStringMember(130, 100)
    serial_num_ps = tlv.OctetStringMember(131, 100)
    country_name_ps = tlv.OctetStringMember(132, 100)
    locality_name_ps = tlv.OctetStringMember(133, 100)
    state_or_province_name_ps = tlv.OctetStringMember(134, 100)
    org_name_ps = tlv.OctetStringMember(135, 100)
    org_unit_name_ps = tlv.OctetStringMember(136, 100)
    title_ps = tlv.OctetStringMember(137, 100)
    name_ps = tlv.OctetStringMember(138, 100)
    given_name_ps = tlv.OctetStringMember(139, 100)
    initials_ps = tlv.OctetStringMember(140, 100)
    gen_qualifier_ps = tlv.OctetStringMember(141, 100)
    dn_qualifier_ps = tlv.OctetStringMember(142, 100)
    pseudonym_ps = tlv.OctetStringMember(143, 100)


class BasicContraints(tlv.Structure):
    # Section 6.5.11.1
    is_ca = tlv.BoolMember(1)
    path_len_constraint = tlv.IntMember(2, signed=False, octets=1, optional=True)


class Extensions(tlv.List):
    # Section 6.5.11
    basic_cnstr = tlv.StructMember(1, BasicContraints)
    key_usage = tlv.IntMember(2, signed=False, octets=2)
    extended_key_usage = tlv.ArrayMember(
        3, tlv.IntMember(None, signed=False, octets=1), max_length=100
    )
    subject_key_id = tlv.OctetStringMember(4, 20)
    authority_key_id = tlv.OctetStringMember(5, 20)
    future_extension = tlv.OctetStringMember(6, 400)


class SignatureAlgorithm(enum.IntEnum):
    # Section 6.5.5
    ECDSA_WITH_SHA256 = 1


class PublicKeyAlgorithm(enum.IntEnum):
    # Section 6.5.8
    EC_PUB_KEY = 1


class EllipticCurveId(enum.IntEnum):
    # Section 6.5.9
    PRIME256V1 = 1


class MatterCertificate(tlv.Structure):
    # Section 6.5.2

    serial_num = tlv.OctetStringMember(1, 20)
    sig_algo = tlv.EnumMember(2, SignatureAlgorithm)
    issuer = tlv.ListMember(3, DNAttribute)
    not_before = tlv.IntMember(4, signed=False, octets=4)
    not_after = tlv.IntMember(5, signed=False, octets=4)
    subject = tlv.ListMember(6, DNAttribute)
    pub_key_algo = tlv.EnumMember(7, PublicKeyAlgorithm)
    ec_curve_id = tlv.EnumMember(8, EllipticCurveId)
    ec_pub_key = tlv.OctetStringMember(9, 65)
    extensions = tlv.ListMember(10, Extensions)
    signature = tlv.OctetStringMember(11, GROUP_SIZE_BYTES * 2)


def Hash(*message) -> bytes:
    h = hashlib.sha256()
    for m in message:
        h.update(m)
    return h.digest()


def HMAC(key, message) -> bytes:
    m = hmac.new(key, digestmod=hashlib.sha256)
    m.update(message)
    return m.digest()


def HKDF_Extract(salt, input_key) -> bytes:
    return HMAC(salt, input_key)


def HKDF_Expand(prk, info, length) -> bytes:
    if length > 255:
        raise ValueError("length must be less than 256")
    last_hash = b""
    bytes_generated = []
    num_bytes_generated = 0
    i = 1
    while num_bytes_generated < length:
        num_bytes_generated += HASH_LEN_BYTES
        # Do the hmac directly so we don't need to allocate a buffer for last_hash + info + i.
        m = hmac.new(prk, digestmod=hashlib.sha256)
        m.update(last_hash)
        m.update(info)
        m.update(struct.pack("b", i))
        last_hash = m.digest()
        bytes_generated.append(last_hash)
        i += 1
    return b"".join(bytes_generated)


def KDF(input_key, salt, info, length):
    if salt is None:
        salt = b"\x00" * HASH_LEN_BYTES
    return HKDF_Expand(HKDF_Extract(salt, input_key), info, length // 8)[: length // 8]


def ECDH(private_key: ecdsa.keys.SigningKey, public_key: bytes) -> bytes:
    ecdh = ecdsa.ecdh.ECDH(ecdsa.NIST256p)
    ecdh.load_private_key(private_key)
    ecdh.load_received_public_key_bytes(public_key)
    return ecdh.generate_sharedsecret_bytes()
