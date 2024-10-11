from circuitmatter.clusters.system_model import user_label, binding

from circuitmatter import data_model


class SimpleDevice:
    def __init__(self):
        self.servers = []
        self.descriptor = data_model.DescriptorCluster()
        device_type = data_model.DescriptorCluster.DeviceTypeStruct()
        device_type.DeviceType = self.DEVICE_TYPE_ID
        device_type.Revision = self.REVISION
        self.descriptor.DeviceTypeList = [device_type]
        self.descriptor.PartsList = []
        self.descriptor.ServerList = []
        self.descriptor.ClientList = []
        self.servers.append(self.descriptor)

        self.binding = binding.BindingCluster()
        self.servers.append(self.binding)

        self.user_label = user_label.UserLabelCluster()
        self.servers.append(self.user_label)
