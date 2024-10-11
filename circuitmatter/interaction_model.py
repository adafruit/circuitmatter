import enum

from . import protocol
from . import tlv


class StatusCode(enum.IntEnum):
    SUCCESS = 0x00
    """Operation was successful."""
    FAILURE = 0x01
    """Operation was not successful."""
    INVALID_SUBSCRIPTION = 0x7D
    """Subscription ID is not active."""
    UNSUPPORTED_ACCESS = 0x7E
    """The sender of the action or command does not have authorization or access."""
    UNSUPPORTED_ENDPOINT = 0x7F
    """The endpoint indicated is unsupported on the node."""
    INVALID_ACTION = 0x80
    """The action is malformed, has missing fields, or fields with invalid values. Action not carried out."""
    UNSUPPORTED_COMMAND = 0x81
    """The indicated command ID is not supported on the cluster instance. Command not carried out."""
    INVALID_COMMAND = 0x85
    """The cluster command is malformed, has missing fields, or fields with invalid values. Command not carried out."""
    UNSUPPORTED_ATTRIBUTE = 0x86
    """The indicated attribute ID, field ID or list entry does not exist for an attribute path."""
    CONSTRAINT_ERROR = 0x87
    """Out of range error or set to a reserved value. Attribute keeps its old value. Note that an attribute value may be out of range if an attribute is related to another, e.g. with minimum and maximum attributes. See the individual attribute descriptions for specific details."""
    UNSUPPORTED_WRITE = 0x88
    """Attempt to write a read-only attribute."""
    RESOURCE_EXHAUSTED = 0x89
    """An action or operation failed due to insufficient available resources."""
    NOT_FOUND = 0x8B
    """The indicated data field or entry could not be found."""
    UNREPORTABLE_ATTRIBUTE = 0x8C
    """Reports cannot be issued for this attribute."""
    INVALID_DATA_TYPE = 0x8D
    """The data type indicated is undefined or invalid for the indicated data field. Command or action not carried out."""
    UNSUPPORTED_READ = 0x8F
    """Attempt to read a write-only attribute."""
    DATA_VERSION_MISMATCH = 0x92
    """Cluster instance data version did not match request path."""
    TIMEOUT = 0x94
    """The transaction was aborted due to time being exceeded."""
    UNSUPPORTED_NODE = 0x9B
    """The node ID indicated is not supported on the node."""
    BUSY = 0x9C
    """The receiver is busy processing another action that prevents the execution of the incoming action."""
    UNSUPPORTED_CLUSTER = 0xC3
    """The cluster indicated is not supported on the endpoint."""
    NO_UPSTREAM_SUBSCRIPTION = 0xC5
    """Used by proxies to convey to clients the lack of an upstream subscription to a source."""
    NEEDS_TIMED_INTERACTION = 0xC6
    """A Untimed Write or Untimed Invoke interaction was used for an attribute or command that requires a Timed Write or Timed Invoke."""
    UNSUPPORTED_EVENT = 0xC7
    """The indicated event ID is not supported on the cluster instance."""
    PATHS_EXHAUSTED = 0xC8
    """The receiver has insufficient resources to support the specified number of paths in the request."""
    TIMED_REQUEST_MISMATCH = 0xC9
    """A request with TimedRequest field set to TRUE was issued outside a Timed transaction or a request with TimedRequest set to FALSE was issued inside a Timed transaction."""
    FAILSAFE_REQUIRED = 0xCA
    """A request requiring a Fail-safe context was invoked without the Fail-Safe context."""
    INVALID_IN_STATE = 0xCB
    """The received request cannot be handled due to the current operational state of the device."""
    NO_COMMAND_RESPONSE = 0xCC
    """A CommandDataIB is missing a response in the InvokeResponses of an Invoke Response action."""


class AttributePathIB(tlv.List):
    """Section 10.6.2"""

    EnableTagCompression = tlv.BoolMember(0, optional=True)
    Node = tlv.IntMember(1, signed=False, octets=8, optional=True)
    Endpoint = tlv.IntMember(2, signed=False, octets=2, optional=True)
    Cluster = tlv.IntMember(3, signed=False, octets=4, optional=True)
    Attribute = tlv.IntMember(4, signed=False, octets=4, optional=True)
    ListIndex = tlv.IntMember(5, signed=False, octets=2, nullable=True, optional=True)
    WildcardPathFlags = tlv.IntMember(6, signed=False, octets=4, optional=True)


class EventPathIB(tlv.List):
    """Section 10.6.8"""

    Node = tlv.IntMember(0, signed=False, octets=8)
    Endpoint = tlv.IntMember(1, signed=False, octets=2)
    Cluster = tlv.IntMember(2, signed=False, octets=4)
    Event = tlv.IntMember(3, signed=False, octets=4)
    IsUrgent = tlv.BoolMember(4)


class EventFilterIB(tlv.Structure):
    """Section 10.6.6"""

    Node = tlv.IntMember(0, signed=False, octets=8)
    EventMinimumInterval = tlv.IntMember(1, signed=False, octets=8)


class ClusterPathIB(tlv.List):
    Node = tlv.IntMember(0, signed=False, octets=8)
    Endpoint = tlv.IntMember(1, signed=False, octets=2)
    Cluster = tlv.IntMember(2, signed=False, octets=4)


class DataVersionFilterIB(tlv.Structure):
    Path = tlv.StructMember(0, ClusterPathIB)
    DataVersion = tlv.IntMember(1, signed=False, octets=4)


class StatusIB(tlv.Structure):
    Status = tlv.EnumMember(0, StatusCode)
    ClusterStatus = tlv.IntMember(1, signed=False, octets=1, optional=True)


class AttributeDataIB(tlv.Structure):
    DataVersion = tlv.IntMember(0, signed=False, octets=4)
    Path = tlv.ListMember(1, AttributePathIB)
    Data = tlv.AnythingMember(2)


class AttributeStatusIB(tlv.Structure):
    Path = tlv.ListMember(0, AttributePathIB)
    Status = tlv.StructMember(1, StatusIB)


class AttributeReportIB(tlv.Structure):
    AttributeStatus = tlv.StructMember(0, AttributeStatusIB, optional=True)
    AttributeData = tlv.StructMember(1, AttributeDataIB, optional=True)


class InteractionModelMessage(tlv.Structure):
    PROTOCOL_ID = protocol.ProtocolId.INTERACTION_MODEL

    InteractionModelRevision = tlv.IntMember(0xFF, signed=False, octets=1, default=11)


class ChunkedMessage(InteractionModelMessage):
    """Chunked messages take multiple encodes or decodes before they are complete."""

    def encode_into(self, buffer: memoryview, offset: int = 0) -> int:
        # Leave room for MoreChunkedMessages, SupressResponse, and InteractionModelRevision.
        buffer[0] = tlv.ElementType.STRUCTURE
        offset += 1
        subbuffer = memoryview(buffer)[: -2 * 2 - 3 - 1]
        del self.MoreChunkedMessages
        for name, descriptor_class in self._members():
            if isinstance(descriptor_class, tlv.ArrayMember):
                try:
                    offset = descriptor_class.encode_into(self, subbuffer, offset)
                except tlv.ArrayEncodingError as e:
                    print("splitting", name, f"[{e.index}:] offset {offset}")
                    offset = e.offset
                    tag = descriptor_class.tag
                    self.values[tag] = self.values[tag][e.index :]
                    self.MoreChunkedMessages = True
            else:
                offset = descriptor_class.encode_into(self, buffer, offset)
        buffer[offset] = tlv.ElementType.END_OF_CONTAINER
        return offset + 1


class ReadRequestMessage(InteractionModelMessage):
    PROTOCOL_OPCODE = protocol.InteractionModelOpcode.READ_REQUEST

    AttributeRequests = tlv.ArrayMember(0, AttributePathIB)
    EventRequests = tlv.ArrayMember(1, EventPathIB)
    EventFilters = tlv.ArrayMember(2, EventFilterIB)
    FabricFiltered = tlv.BoolMember(3)
    DataVersionFilters = tlv.ArrayMember(4, DataVersionFilterIB)


class WriteRequestMessage(ChunkedMessage):
    PROTOCOL_OPCODE = protocol.InteractionModelOpcode.WRITE_REQUEST

    SuppressResponse = tlv.BoolMember(0, optional=True)
    TimedRequest = tlv.BoolMember(1)
    WriteRequests = tlv.ArrayMember(2, AttributeDataIB)
    MoreChunkedMessages = tlv.BoolMember(3, optional=True)


class WriteResponseMessage(InteractionModelMessage):
    PROTOCOL_OPCODE = protocol.InteractionModelOpcode.WRITE_RESPONSE

    WriteResponses = tlv.ArrayMember(0, AttributeStatusIB)


class EventStatusIB(tlv.Structure):
    Path = tlv.StructMember(0, EventPathIB)
    Status = tlv.StructMember(1, StatusIB)


class EventDataIB(tlv.Structure):
    Path = tlv.StructMember(0, EventPathIB)
    EventNumber = tlv.IntMember(1, signed=False, octets=8)
    PriorityLevel = tlv.IntMember(2, signed=False, octets=1)

    # Only one of the below values
    EpochTimestamp = tlv.IntMember(3, signed=False, octets=8, optional=True)
    SystemTimestamp = tlv.IntMember(4, signed=False, octets=8, optional=True)
    DeltaEpochTimestamp = tlv.IntMember(5, signed=True, octets=8, optional=True)
    DeltaSystemTimestamp = tlv.IntMember(6, signed=True, octets=8, optional=True)

    Data = tlv.AnythingMember(7)


class EventReportIB(tlv.Structure):
    EventStatus = tlv.StructMember(0, EventStatusIB)
    EventData = tlv.StructMember(1, EventDataIB)


class ReportDataMessage(ChunkedMessage):
    PROTOCOL_OPCODE = protocol.InteractionModelOpcode.REPORT_DATA

    SubscriptionId = tlv.IntMember(0, signed=False, octets=4, optional=True)
    AttributeReports = tlv.ArrayMember(1, AttributeReportIB, optional=True)
    EventReports = tlv.ArrayMember(2, EventReportIB, optional=True)
    MoreChunkedMessages = tlv.BoolMember(3, optional=True)
    SuppressResponse = tlv.BoolMember(4, optional=True)


class CommandPathIB(tlv.List):
    Endpoint = tlv.IntMember(0, signed=False, octets=2)
    Cluster = tlv.IntMember(1, signed=False, octets=4)
    Command = tlv.IntMember(2, signed=False, octets=4)


class CommandDataIB(tlv.Structure):
    CommandPath = tlv.ListMember(0, CommandPathIB)
    CommandFields = tlv.AnythingMember(1, optional=True)
    CommandRef = tlv.NumberMember(2, "H", optional=True)


class CommandStatusIB(tlv.Structure):
    CommandPath = tlv.ListMember(0, CommandPathIB)
    Status = tlv.StructMember(1, StatusIB)
    CommandRef = tlv.NumberMember(2, "H", optional=True)


class InvokeResponseIB(tlv.Structure):
    Command = tlv.StructMember(0, CommandDataIB, optional=True)
    Status = tlv.StructMember(1, CommandStatusIB, optional=True)


class InvokeRequestMessage(InteractionModelMessage):
    PROTOCOL_OPCODE = protocol.InteractionModelOpcode.INVOKE_REQUEST

    SuppressResponse = tlv.BoolMember(0)
    TimedRequest = tlv.BoolMember(1)
    InvokeRequests = tlv.ArrayMember(2, CommandDataIB)


class InvokeResponseMessage(InteractionModelMessage):
    PROTOCOL_OPCODE = protocol.InteractionModelOpcode.INVOKE_RESPONSE

    SuppressResponse = tlv.BoolMember(0)
    InvokeResponses = tlv.ArrayMember(1, InvokeResponseIB)
    MoreChunkedMessages = tlv.BoolMember(2, optional=True)


class SubscribeRequestMessage(InteractionModelMessage):
    PROTOCOL_OPCODE = protocol.InteractionModelOpcode.SUBSCRIBE_REQUEST

    KeepSubscriptions = tlv.BoolMember(0)
    MinIntervalFloor = tlv.IntMember(1, signed=False, octets=2)
    MaxIntervalCeiling = tlv.IntMember(2, signed=False, octets=2)
    AttributeRequests = tlv.ArrayMember(3, AttributePathIB, optional=True)
    EventRequests = tlv.ArrayMember(4, EventPathIB, optional=True)
    EventFilters = tlv.ArrayMember(5, EventFilterIB, optional=True)
    FabricFiltered = tlv.BoolMember(7)
    DataVersionFilters = tlv.ArrayMember(8, DataVersionFilterIB, optional=True)


class StatusResponseMessage(InteractionModelMessage):
    PROTOCOL_OPCODE = protocol.InteractionModelOpcode.STATUS_RESPONSE

    Status = tlv.EnumMember(0, StatusCode)


class SubscribeResponseMessage(InteractionModelMessage):
    PROTOCOL_OPCODE = protocol.InteractionModelOpcode.SUBSCRIBE_RESPONSE

    SubscriptionId = tlv.IntMember(0, signed=False, octets=4)
    MaxInterval = tlv.IntMember(2, signed=False, octets=2)
