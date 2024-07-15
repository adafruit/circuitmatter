"""Pure Python implementation of the Matter IOT protocol."""

import enum

from . import tlv

__version__ = "0.0.0"

# descriminator = 3840
# avahi = subprocess.Popen(["avahi-publish-service", "-v", f"--subtype=_L{descriminator}._sub._matterc._udp", "--subtype=_CM._sub._matterc._udp", "FA93546B21F5FB54", "_matterc._udp", "5540", "PI=", "PH=33", "CM=1", f"D={descriminator}", "CRI=3000", "CRA=4000", "T=1", "VP=65521+32769"])

# # Define the UDP IP address and port
# UDP_IP = "::"  # Listen on all available network interfaces
# UDP_PORT = 5540

# # Create the UDP socket
# sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

# # Bind the socket to the IP and port
# sock.bind((UDP_IP, UDP_PORT))

# print(f"Listening on UDP port {UDP_PORT}")

unsecured_session_context = {}


class ProtocolId(enum.Enum):
    SECURE_CHANNEL = 0
    INTERACTION_MODEL = 1
    BDX = 2
    USER_DIRECTED_COMMISSIONING = 3
    FOR_TESTING = 4


class SecurityFlags(enum.Flag):
    P = 1 << 7
    C = 1 << 6
    MX = 1 << 5


class ExchangeFlags(enum.Flag):
    V = 1 << 4
    SX = 1 << 3
    R = 1 << 2
    A = 1 << 1
    I = 1 << 0  # noqa: E741


class SecureProtocolOpcode(enum.Enum):
    MSG_COUNTER_SYNC_REQ = 0x00
    """The Message Counter Synchronization Request message queries the current message counter from a peer to bootstrap replay protection."""

    MSG_COUNTER_SYNC_RSP = 0x01
    """The Message Counter Synchronization Response message provides the current message counter from a peer to bootstrap replay protection."""

    MRP_STANDALONE_ACK = 0x10
    """This message is dedicated for the purpose of sending a stand-alone acknowledgement when there is no other data message available to piggyback an acknowledgement on top of."""

    PBKDF_PARAM_REQUEST = 0x20
    """The request for PBKDF parameters necessary to complete the PASE protocol."""

    PBKDF_PARAM_RESPONSE = 0x21
    """The PBKDF parameters sent in response to PBKDF-ParamRequest during the PASE protocol."""

    PASE_PAKE1 = 0x22
    """The first PAKE message of the PASE protocol."""

    PASE_PAKE2 = 0x23
    """The second PAKE message of the PASE protocol."""

    PASE_PAKE3 = 0x24
    """The third PAKE message of the PASE protocol."""

    CASE_SIGMA1 = 0x30
    """The first message of the CASE protocol."""

    CASE_SIGMA2 = 0x31
    """The second message of the CASE protocol."""

    CASE_SIGMA3 = 0x32
    """The third message of the CASE protocol."""

    CASE_SIGMA2_RESUME = 0x33
    """The second resumption message of the CASE protocol."""

    STATUS_REPORT = 0x40
    """The Status Report message encodes the result of an operation in the Secure Channel as well as other protocols."""

    ICD_CHECK_IN = 0x50
    """The Check-in message notifies a client that the ICD is available for communication."""


PROTOCOL_OPCODES = {
    ProtocolId.SECURE_CHANNEL: SecureProtocolOpcode,
}


# session-parameter-struct => STRUCTURE [ tag-order ]
# {
# SESSION_IDLE_INTERVAL
#  [1, optional] : UNSIGNED INTEGER [ range 32-bits ],
# SESSION_ACTIVE_INTERVAL
#  [2, optional] : UNSIGNED INTEGER [ range 32-bits ],
# SESSION_ACTIVE_THRESHOLD
#  [3, optional] : UNSIGNED INTEGER [ range 16-bits ],
# DATA_MODEL_REVISION
#  [4]
#  : UNSIGNED INTEGER [ range 16-bits ],
# INTERACTION_MODEL_REVISION [5]
#  : UNSIGNED INTEGER [ range 16-bits ],
# SPECIFICATION_VERSION
#  [6]
#  : UNSIGNED INTEGER [ range 32-bits ],
# MAX_PATHS_PER_INVOKE
#  [7]
#  : UNSIGNED INTEGER [ range 16-bits ],
# }
class SessionParameterStruct(tlv.TLVStructure):
    session_idle_interval = tlv.IntegerMember(1, "<I", optional=True)
    session_active_interval = tlv.IntegerMember(2, "<I", optional=True)
    session_active_threshold = tlv.IntegerMember(3, "<H", optional=True)
    data_model_revision = tlv.IntegerMember(4, "<H")
    interaction_model_revision = tlv.IntegerMember(5, "<H")
    specification_version = tlv.IntegerMember(6, "<I")
    max_paths_per_invoke = tlv.IntegerMember(7, "<H")


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
class PBKDFParamRequest(tlv.TLVStructure):
    initiatorRandom = tlv.OctetStringMember(1, 32)
    initiatorSessionId = tlv.IntegerMember(2, "<H")
    passcodeId = tlv.IntegerMember(3, "<H")
    hasPBKDFParameters = tlv.BoolMember(4)
    initiatorSessionParams = tlv.StructMember(5, SessionParameterStruct, optional=True)


# Crypto_PBKDFParameterSet => STRUCTURE [ tag-order ]
# {
# iterations [1] : UNSIGNED INTEGER [ range 32-bits ],
# salt [2] : OCTET STRING [ length 16..32 ],
# }
class Crypto_PBKDFParameterSet(tlv.TLVStructure):
    iterations = tlv.IntegerMember(1, "<I")
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
class PBKDFParamResponse(tlv.TLVStructure):
    initiatorRandom = tlv.OctetStringMember(1, 32)
    responderRandom = tlv.OctetStringMember(2, 32)
    responderSessionId = tlv.IntegerMember(3, "<H")
    pbkdf_parameters = tlv.StructMember(4, Crypto_PBKDFParameterSet)
    responderSessionParams = tlv.StructMember(5, SessionParameterStruct, optional=True)
