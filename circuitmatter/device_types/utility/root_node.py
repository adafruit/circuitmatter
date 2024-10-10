from circuitmatter import data_model
from circuitmatter.clusters import core


class RootNode:
    DEVICE_TYPE_ID = 0x0011
    REVISION = 2

    def __init__(self, random_source, mdns_server, port, vendor_id, product_id):
        self.servers = []

        basic_info = data_model.BasicInformationCluster()
        basic_info.vendor_id = vendor_id
        basic_info.product_id = product_id
        basic_info.product_name = "CircuitMatter"
        self.servers.append(basic_info)
        access_control = data_model.AccessControlCluster()
        self.servers.append(access_control)
        group_keys = core.GroupKeyManagementCluster()
        self.servers.append(group_keys)
        network_info = data_model.NetworkCommissioningCluster()
        network_info.feature_map = (
            data_model.NetworkCommissioningCluster.FeatureBitmap.WIFI_NETWORK_INTERFACE
        )

        ethernet = data_model.NetworkCommissioningCluster.NetworkInfoStruct()
        ethernet.NetworkID = "enp13s0".encode("utf-8")
        ethernet.Connected = True
        network_info.networks = [ethernet]
        network_info.connect_max_time_seconds = 10
        network_info.last_network_status = (
            data_model.NetworkCommissioningCluster.NetworkCommissioningStatus.SUCCESS
        )
        network_info.last_network_id = ethernet.NetworkID
        self.servers.append(network_info)
        general_commissioning = core.GeneralCommissioningCluster()
        self.servers.append(general_commissioning)
        self.noc = core.NodeOperationalCredentialsCluster(
            group_keys, random_source, mdns_server, port
        )
        self.servers.append(self.noc)
