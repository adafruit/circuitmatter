from . import tlv


class AttributePathIB(tlv.TLVStructure):
    """Section 10.6.2"""

    EnableTagCompression = tlv.BoolMember(0, optional=True)
    Node = tlv.IntMember(1, signed=False, octets=8, optional=True)
    Endpoint = tlv.IntMember(2, signed=False, octets=2, optional=True)
    Cluster = tlv.IntMember(3, signed=False, octets=4, optional=True)
    Attribute = tlv.IntMember(4, signed=False, octets=4, optional=True)
    ListIndex = tlv.IntMember(5, signed=False, octets=2, nullable=True, optional=True)
    WildcardPathFlags = tlv.IntMember(6, signed=False, octets=4, optional=True)


class EventPathIB(tlv.TLVStructure):
    """Section 10.6.8"""

    Node = tlv.IntMember(0, signed=False, octets=8)
    Endpoint = tlv.IntMember(1, signed=False, octets=2)
    Cluster = tlv.IntMember(2, signed=False, octets=4)
    Event = tlv.IntMember(3, signed=False, octets=4)
    IsUrgent = tlv.BoolMember(4)


class EventFilterIB(tlv.TLVStructure):
    """Section 10.6.6"""

    Node = tlv.IntMember(0, signed=False, octets=8)
    EventMinimumInterval = tlv.IntMember(1, signed=False, octets=8)


class ClusterPathIB(tlv.TLVStructure):
    Node = tlv.IntMember(0, signed=False, octets=8)
    Endpoint = tlv.IntMember(1, signed=False, octets=2)
    Cluster = tlv.IntMember(2, signed=False, octets=4)


class DataVersionFilterIB(tlv.TLVStructure):
    Path = tlv.StructMember(0, ClusterPathIB)
    DataVersion = tlv.IntMember(1, signed=False, octets=4)


class StatusIB(tlv.TLVStructure):
    Status = tlv.IntMember(0, signed=False, octets=1)
    ClusterStatus = tlv.IntMember(1, signed=False, octets=1)


class AttributeDataIB(tlv.TLVStructure):
    DataVersion = tlv.IntMember(0, signed=False, octets=4)
    Path = tlv.StructMember(1, AttributePathIB)
    Data = tlv.AnythingMember(2)


class AttributeStatusIB(tlv.TLVStructure):
    Path = tlv.StructMember(0, AttributePathIB)
    Status = tlv.StructMember(1, StatusIB)


class AttributeReportIB(tlv.TLVStructure):
    AttributeStatus = tlv.StructMember(0, AttributeStatusIB)
    AttributeData = tlv.StructMember(1, AttributeDataIB)


class ReadRequestMessage(tlv.TLVStructure):
    AttributeRequests = tlv.ArrayMember(0, tlv.List(AttributePathIB))
    EventRequests = tlv.ArrayMember(1, EventPathIB)
    EventFilters = tlv.ArrayMember(2, EventFilterIB)
    FabricFiltered = tlv.BoolMember(3)
    DataVersionFilters = tlv.ArrayMember(4, DataVersionFilterIB)


class EventStatusIB(tlv.TLVStructure):
    Path = tlv.StructMember(0, EventPathIB)
    Status = tlv.StructMember(1, StatusIB)


class EventDataIB(tlv.TLVStructure):
    Path = tlv.StructMember(0, EventPathIB)
    EventNumber = tlv.IntMember(1, signed=False, octets=8)
    PriorityLevel = tlv.IntMember(2, signed=False, octets=1)

    # Only one of the below values
    EpochTimestamp = tlv.IntMember(3, signed=False, octets=8, optional=True)
    SystemTimestamp = tlv.IntMember(4, signed=False, octets=8, optional=True)
    DeltaEpochTimestamp = tlv.IntMember(5, signed=True, octets=8, optional=True)
    DeltaSystemTimestamp = tlv.IntMember(6, signed=True, octets=8, optional=True)

    Data = tlv.AnythingMember(7)


class EventReportIB(tlv.TLVStructure):
    EventStatus = tlv.StructMember(0, EventStatusIB)
    EventData = tlv.StructMember(1, EventDataIB)


class ReportDataMessage(tlv.TLVStructure):
    SubscriptionId = tlv.IntMember(0, signed=False, octets=4, optional=True)
    AttributeReports = tlv.ArrayMember(1, AttributeReportIB, optional=True)
    EventReports = tlv.ArrayMember(2, EventReportIB, optional=True)
    MoreChunkedMessages = tlv.BoolMember(3, optional=True)
    SuppressResponse = tlv.BoolMember(4, optional=True)
