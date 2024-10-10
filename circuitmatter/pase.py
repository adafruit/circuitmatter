from . import crypto
from . import protocol
from . import tlv
from . import session

import hashlib
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from ecdsa.ellipticcurve import AbstractPoint, Point, PointJacobi
from ecdsa.curves import NIST256p


class PASEMessage(tlv.Structure):
    PROTOCOL_ID = protocol.ProtocolId.SECURE_CHANNEL


# pbkdfparamreq-struct => STRUCTURE [ tag-order ]
# {
# initiatorRandom
#  [1] : OCTET STRING [ length 32 ],
# initiatorSessionId
#  [2] : UNSIGNED INTEGER [ range 16-bits ],
# passcodeId
#  [3] : UNSIGNED INTEGER [ length 16-bits ],
# hasPBKDFParameters
#  [4] : BOOLEAN,
# initiatorSessionParams [5, optional] : session-parameter-struct
# }
class PBKDFParamRequest(PASEMessage):
    PROTOCOL_OPCODE = protocol.SecureProtocolOpcode.PBKDF_PARAM_REQUEST

    initiatorRandom = tlv.OctetStringMember(1, 32)
    initiatorSessionId = tlv.IntMember(2, signed=False, octets=2)
    passcodeId = tlv.IntMember(3, signed=False, octets=2)
    hasPBKDFParameters = tlv.BoolMember(4)
    initiatorSessionParams = tlv.StructMember(
        5, session.SessionParameterStruct, optional=True
    )


# Crypto_PBKDFParameterSet => STRUCTURE [ tag-order ]
# {
# iterations [1] : UNSIGNED INTEGER [ range 32-bits ],
# salt [2] : OCTET STRING [ length 16..32 ],
# }
class Crypto_PBKDFParameterSet(tlv.Structure):
    iterations = tlv.IntMember(1, signed=False, octets=4)
    salt = tlv.OctetStringMember(2, 32)


# pbkdfparamresp-struct => STRUCTURE [ tag-order ]
# {
# initiatorRandom
#  [1] : OCTET STRING [ length 32 ],
# responderRandom
#  [2] : OCTET STRING [ length 32 ],
# responderSessionId
#  [3] : UNSIGNED INTEGER [ range 16-bits ],
# pbkdf_parameters
#  [4] : Crypto_PBKDFParameterSet,
# responderSessionParams [5, optional] : session-parameter-struct
# }
class PBKDFParamResponse(PASEMessage):
    PROTOCOL_OPCODE = protocol.SecureProtocolOpcode.PBKDF_PARAM_RESPONSE
    initiatorRandom = tlv.OctetStringMember(1, 32)
    responderRandom = tlv.OctetStringMember(2, 32)
    responderSessionId = tlv.IntMember(3, signed=False, octets=2)
    pbkdf_parameters = tlv.StructMember(4, Crypto_PBKDFParameterSet)
    responderSessionParams = tlv.StructMember(
        5, session.SessionParameterStruct, optional=True
    )


class PAKE1(PASEMessage):
    PROTOCOL_OPCODE = protocol.SecureProtocolOpcode.PASE_PAKE1
    pA = tlv.OctetStringMember(1, crypto.PUBLIC_KEY_SIZE_BYTES)


class PAKE2(PASEMessage):
    PROTOCOL_OPCODE = protocol.SecureProtocolOpcode.PASE_PAKE2
    pB = tlv.OctetStringMember(1, crypto.PUBLIC_KEY_SIZE_BYTES)
    cB = tlv.OctetStringMember(2, crypto.HASH_LEN_BYTES)


class PAKE3(PASEMessage):
    PROTOCOL_OPCODE = protocol.SecureProtocolOpcode.PASE_PAKE3
    cA = tlv.OctetStringMember(1, crypto.HASH_LEN_BYTES)


M = PointJacobi.from_bytes(
    NIST256p.curve,
    b"\x02\x88\x6e\x2f\x97\xac\xe4\x6e\x55\xba\x9d\xd7\x24\x25\x79\xf2\x99\x3b\x64\xe1\x6e\xf3\xdc\xab\x95\xaf\xd4\x97\x33\x3d\x8f\xa1\x2f",
)
N = PointJacobi.from_bytes(
    NIST256p.curve,
    b"\x03\xd8\xbb\xd6\xc6\x39\xc6\x29\x37\xb0\x4d\x99\x7f\x38\xc3\x77\x07\x19\xc6\x29\xd7\x01\x4d\x49\xa2\x4b\x4f\x98\xba\xa1\x29\x2b\x49",
)
crypto.W_SIZE_BYTES = crypto.GROUP_SIZE_BYTES + 8


# in the spake2p math P is NIST256p.generator
# in the spake2p math p is NIST256p.order
def _pbkdf2(passcode, salt, iterations):
    ws = hashlib.pbkdf2_hmac(
        "sha256", struct.pack("<I", passcode), salt, iterations, crypto.W_SIZE_BYTES * 2
    )
    w0 = int.from_bytes(ws[: crypto.W_SIZE_BYTES], byteorder="big") % NIST256p.order
    w1 = int.from_bytes(ws[crypto.W_SIZE_BYTES :], byteorder="big") % NIST256p.order
    return w0, w1


def initiator_values(passcode, salt, iterations) -> tuple[bytes, bytes]:
    w0, w1 = _pbkdf2(passcode, salt, iterations)
    return w0.to_bytes(NIST256p.baselen, byteorder="big"), w1.to_bytes(
        NIST256p.baselen, byteorder="big"
    )


def verifier_values(passcode: int, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    w0, w1 = _pbkdf2(passcode, salt, iterations)
    L = NIST256p.generator * w1

    return w0.to_bytes(NIST256p.baselen, byteorder="big"), L.to_bytes("uncompressed")


# w0 and w1 are big-endian encoded
def Crypto_pA(w0, w1) -> bytes:
    return b""


def Crypto_pB(random_source, w0: int, L: Point) -> tuple[int, AbstractPoint]:
    y = random_source.randbelow(NIST256p.order)
    Y = y * NIST256p.generator + w0 * N
    return y, Y


def Crypto_Transcript(context, pA, pB, Z, V, w0) -> bytes:
    elements = [
        context,
        b"",
        b"",
        M.to_bytes("uncompressed"),
        N.to_bytes("uncompressed"),
        pA,
        pB,
        Z,
        V,
        w0,
    ]
    total_length = 0
    for e in elements:
        total_length += len(e) + 8
    tt = bytearray(total_length)
    offset = 0
    for e in elements:
        struct.pack_into("<Q", tt, offset, len(e))
        offset += 8

        tt[offset : offset + len(e)] = e
        offset += len(e)
    return tt


def KDF(salt, key, info):
    # Section 3.10 defines the mapping from KDF to Crypto_KDF but it is wrong!
    # The arg order is correct above.
    return crypto.KDF(key, salt, info, crypto.HASH_LEN_BITS)


def Crypto_P2(tt, pA, pB) -> tuple[bytes, bytes, bytes]:
    KaKe = crypto.Hash(tt)
    Ka = KaKe[: crypto.HASH_LEN_BYTES // 2]
    Ke = KaKe[crypto.HASH_LEN_BYTES // 2 :]
    # https://github.com/project-chip/connectedhomeip/blob/c88d5cf83cd3e3323ac196630acc34f196a2f405/src/crypto/CHIPCryptoPAL.cpp#L458-L468
    KcAKcB = KDF(None, Ka, b"ConfirmationKeys")
    KcA = KcAKcB[: crypto.HASH_LEN_BYTES // 2]
    KcB = KcAKcB[crypto.HASH_LEN_BYTES // 2 :]
    cA = crypto.HMAC(KcA, pB)
    cB = crypto.HMAC(KcB, pA)
    return (cA, cB, Ke)


def compute_session_keys(Ke, secure_session_context):
    keys = crypto.KDF(
        Ke,
        b"",
        b"SessionKeys",
        3 * crypto.SYMMETRIC_KEY_LENGTH_BITS,
    )
    secure_session_context.i2r_key = keys[: crypto.SYMMETRIC_KEY_LENGTH_BYTES]
    secure_session_context.i2r = AESCCM(
        secure_session_context.i2r_key,
        tag_length=crypto.AEAD_MIC_LENGTH_BYTES,
    )
    secure_session_context.r2i_key = keys[
        crypto.SYMMETRIC_KEY_LENGTH_BYTES : 2 * crypto.SYMMETRIC_KEY_LENGTH_BYTES
    ]
    secure_session_context.r2i = AESCCM(
        secure_session_context.r2i_key,
        tag_length=crypto.AEAD_MIC_LENGTH_BYTES,
    )
    secure_session_context.attestation_challenge = keys[
        2 * crypto.SYMMETRIC_KEY_LENGTH_BYTES : 3 * crypto.SYMMETRIC_KEY_LENGTH_BYTES
    ]


def compute_verification(random_source, pake1, pake2, context, verifier):
    w0 = memoryview(verifier)[: crypto.GROUP_SIZE_BYTES]
    L = memoryview(verifier)[crypto.GROUP_SIZE_BYTES :]
    L = Point.from_bytes(NIST256p.curve, L)
    w0 = int.from_bytes(w0, byteorder="big")
    y, Y = Crypto_pB(random_source, w0, L)
    # pB is Y encoded uncompressed
    # pA is X encoded uncompressed
    pake2.pB = Y.to_bytes("uncompressed")
    h = NIST256p.curve.cofactor()
    # Use negation because the class doesn't support subtraction. 🤦
    X = Point.from_bytes(NIST256p.curve, pake1.pA)
    Z = h * y * (X + (-(w0 * M)))
    # Z is wrong. V is right
    V = h * y * L
    tt = Crypto_Transcript(
        context,
        pake1.pA,
        pake2.pB,
        Z.to_bytes("uncompressed"),
        V.to_bytes("uncompressed"),
        w0.to_bytes(NIST256p.baselen, byteorder="big"),
    )
    cA, cB, Ke = Crypto_P2(tt, pake1.pA, pake2.pB)
    pake2.cB = cB
    return cA, Ke


def _write_bits(buf, offset, bits, value) -> int:
    while bits > 0:
        bits_remaining = 8 - offset % 8
        write_bits = min(bits, bits_remaining)
        mask = (1 << write_bits) - 1
        buf[offset // 8] |= (value & mask) << (offset % 8)
        offset += write_bits
        bits -= write_bits
        value >>= write_bits
    return offset


def _base38_encode(buf) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-."
    encoded = []
    for i in range(0, len(buf), 3):
        value = 0
        remaining = min(3, len(buf) - i)
        print("remaining", remaining)
        for j in range(remaining):
            value |= buf[i + j] << (j * 8)
        outputs = 5
        if remaining == 2:
            outputs = 4
        elif remaining == 1:
            outputs = 2
        for j in range(outputs):
            encoded.append(alphabet[value % 38])
            value //= 38
        print(encoded)
    return "".join(encoded)


def show_qr_code(vendor_id, product_id, discriminator, passcode):
    total_bits = 3 + 16 * 2 + 2 + 8 + 12 + 27 + 4
    total_bytes = total_bits // 8
    buf = bytearray(total_bytes)

    discovery = 1 << 2  # On network already

    offset = 0
    offset = _write_bits(buf, offset, 3, 0)
    offset = _write_bits(buf, offset, 16, vendor_id)
    offset = _write_bits(buf, offset, 16, product_id)
    offset = _write_bits(buf, offset, 2, 0)
    offset = _write_bits(buf, offset, 8, discovery)
    offset = _write_bits(buf, offset, 12, discriminator)
    offset = _write_bits(buf, offset, 27, passcode)
    print(buf.hex(" "))

    encoded = _base38_encode(buf)

    import qrcode

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data("MT:")
    qr.add_data(encoded)
    qr.print_ascii()
