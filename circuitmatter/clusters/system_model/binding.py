from circuitmatter import data_model
from circuitmatter import tlv


class BindingCluster(data_model.Cluster):
    CLUSTER_ID = 0x001E
    cluster_revision = 1

    class TargetStruct(tlv.Structure):
        Node = data_model.NodeId(1, optional=True)
        Group = data_model.GroupId(2, optional=True)
        Endpoint = data_model.EndpointNumber(3, optional=True)
        Cluster = data_model.ClusterId(4, optional=True)

    Binding = data_model.ListAttribute(
        0x0000, TargetStruct, default=[], N_nonvolatile=True
    )
