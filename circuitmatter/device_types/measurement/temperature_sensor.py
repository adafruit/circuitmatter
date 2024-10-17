from circuitmatter.clusters.general.identify import Identify
from circuitmatter.clusters.general.temperature_measurement import TemperatureMeasurement

from .. import simple_device


class TemperatureSensor(simple_device.SimpleDevice):
    DEVICE_TYPE_ID = 0x0302
    REVISION = 2

    def __init__(self, name):
        super().__init__(name)

        self._identify = Identify()
        self.servers.append(self._identify)

        self._temp = TemperatureMeasurement()
        self.servers.append(self._temp)

        self._temp.MeasuredValue = 1850 # 18.5°C * 100
  
