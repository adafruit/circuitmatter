from .dimmable import DimmableLight

from circuitmatter.clusters.lighting import color_control


class ColorTemperatureLight(DimmableLight):
    DEVICE_TYPE_ID = 0x010C
    REVISION = 4

    def __init__(self, name):
        super().__init__(name)

        self._color_control = color_control.ColorControl()
        self._color_control.feature_map |= color_control.FeatureBitmap.COLOR_TEMPERATURE

        self.servers.append(self._color_control)

    @property
    def color_rgb(self):
        raise NotImplementedError()

    @color_rgb.setter
    def color_rgb(self, value):
        raise NotImplementedError()
