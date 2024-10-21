from .on_off import OnOffLight

from circuitmatter.clusters.general import level_control


class DimmableLight(OnOffLight):
    DEVICE_TYPE_ID = 0x0101
    REVISION = 3

    def __init__(self, name):
        super().__init__(name)

        self._level_control = level_control.LevelControl()
        self._level_control.feature_map |= level_control.FeatureBitmap.LIGHTING
        self._level_control.min_level = 1
        self._level_control.max_level = 254
        self.servers.append(self._level_control)

        self._level_control.move_to_level_with_on_off = self._move_to_level_with_on_off

    def _move_to_level_with_on_off(self, session, value):
        try:
            self.brightness = value.Level / self._level_control.max_level
        except Exception as e:
            print(f"Error setting brightness: {e}")
            return
        self._level_control.CurrentLevel = value.Level

    @property
    def brightness(self):
        return self._level_control.CurrentLevel / self._level_control.max_level

    @brightness.setter
    def brightness(self, value):
        raise NotImplementedError()
