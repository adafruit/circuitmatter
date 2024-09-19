from . import tlv

# Section 3.6

CRYPTO_SYMMETRIC_KEY_LENGTH_BITS = 128
CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES = 16
CRYPTO_AEAD_MIC_LENGTH_BITS = 128
CRYPTO_AEAD_MIC_LENGTH_BYTES = 16
CRYPTO_AEAD_NONCE_LENGTH_BYTES = 13


class SessionParameterStruct(tlv.Structure):
    session_idle_interval = tlv.IntMember(1, signed=False, octets=4, optional=True)
    session_active_interval = tlv.IntMember(2, signed=False, octets=4, optional=True)
    session_active_threshold = tlv.IntMember(3, signed=False, octets=2, optional=True)
    data_model_revision = tlv.IntMember(4, signed=False, octets=2)
    interaction_model_revision = tlv.IntMember(5, signed=False, octets=2)
    specification_version = tlv.IntMember(6, signed=False, octets=4)
    max_paths_per_invoke = tlv.IntMember(7, signed=False, octets=2)
