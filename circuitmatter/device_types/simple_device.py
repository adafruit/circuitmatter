from circuitmatter.clusters.system_model import binding, descriptor, user_label


class SimpleDevice:
    def __init__(self):
        self.servers = []
        self.descriptor = descriptor.DescriptorCluster()
        device_type = descriptor.DescriptorCluster.DeviceTypeStruct()
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
