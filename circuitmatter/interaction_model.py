from . import tlv


class AttributePathIB(tlv.List):
    """Section 10.6.2"""

    EnableTagCompression = tlv.BoolMember(0, optional=True)
    Node = tlv.IntMember(1, signed=False, octets=8, optional=True)
    Endpoint = tlv.IntMember(2, signed=False, octets=2, optional=True)
    Cluster = tlv.IntMember(3, signed=False, octets=4, optional=True)
    Attribute = tlv.IntMember(4, signed=False, octets=4, optional=True)
    ListIndex = tlv.IntMember(5, signed=False, octets=2, nullable=True, optional=True)
    WildcardPathFlags = tlv.IntMember(6, signed=False, octets=4, optional=True)


class EventPathIB(tlv.Structure):
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
    Status = tlv.IntMember(0, signed=False, octets=1)
    ClusterStatus = tlv.IntMember(1, signed=False, octets=1)


class AttributeDataIB(tlv.Structure):
    DataVersion = tlv.IntMember(0, signed=False, octets=4)
    Path = tlv.StructMember(1, AttributePathIB)
    Data = tlv.AnythingMember(2)


class AttributeStatusIB(tlv.Structure):
    Path = tlv.StructMember(0, AttributePathIB)
    Status = tlv.StructMember(1, StatusIB)


class AttributeReportIB(tlv.Structure):
    AttributeStatus = tlv.StructMember(0, AttributeStatusIB)
    AttributeData = tlv.StructMember(1, AttributeDataIB)


class ReadRequestMessage(tlv.Structure):
    AttributeRequests = tlv.ArrayMember(0, AttributePathIB)
    EventRequests = tlv.ArrayMember(1, EventPathIB)
    EventFilters = tlv.ArrayMember(2, EventFilterIB)
    FabricFiltered = tlv.BoolMember(3)
    DataVersionFilters = tlv.ArrayMember(4, DataVersionFilterIB)


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


class ReportDataMessage(tlv.Structure):
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
    Command = tlv.StructMember(0, CommandDataIB)
    Status = tlv.StructMember(1, CommandStatusIB)


class InvokeRequestMessage(tlv.Structure):
    SuppressResponse = tlv.BoolMember(0)
    TimedRequest = tlv.BoolMember(1)
    InvokeRequests = tlv.ArrayMember(2, CommandDataIB)


class InvokeResponseMessage(tlv.Structure):
    SuppressResponse = tlv.BoolMember(0)
    InvokeResponses = tlv.ArrayMember(1, InvokeResponseIB)
    MoreChunkedMessages = tlv.BoolMember(2, optional=True)
