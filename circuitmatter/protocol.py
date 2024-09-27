import enum


class SecureProtocolOpcode(enum.IntEnum):
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


class InteractionModelOpcode(enum.IntEnum):
    STATUS_RESPONSE = 0x01
    READ_REQUEST = 0x02
    SUBSCRIBE_REQUEST = 0x03
    SUBSCRIBE_RESPONSE = 0x04
    REPORT_DATA = 0x05
    WRITE_REQUEST = 0x06
    WRITE_RESPONSE = 0x07
    INVOKE_REQUEST = 0x08
    INVOKE_RESPONSE = 0x09
    TIMED_REQUEST = 0x0A


class ProtocolId(enum.IntEnum):
    SECURE_CHANNEL = 0
    INTERACTION_MODEL = 1
    BDX = 2
    USER_DIRECTED_COMMISSIONING = 3
    FOR_TESTING = 4

    def ProtocolOpcode(self, opcode_id: int):
        if self == self.SECURE_CHANNEL:
            return SecureProtocolOpcode(opcode_id)
        elif self == self.INTERACTION_MODEL:
            return InteractionModelOpcode(opcode_id)
