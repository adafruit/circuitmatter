import colorsys

from .color_temperature import ColorTemperatureLight


from circuitmatter.clusters.lighting import color_control


class ExtendedColorLight(ColorTemperatureLight):
    DEVICE_TYPE_ID = 0x010D
    REVISION = 4

    def __init__(self, name):
        super().__init__(name)

        self._color_control.feature_map |= (
            color_control.FeatureBitmap.HUE_SATURATION
            | color_control.FeatureBitmap.ENHANCED_HUE
            | color_control.FeatureBitmap.COLOR_LOOP
            | color_control.FeatureBitmap.XY
        )

        self._color_control.move_to_hue_and_saturation = (
            self._move_to_hue_and_saturation
        )

    def _move_to_hue_and_saturation(self, session, value):
        try:
            r, g, b = colorsys.hsv_to_rgb(value.Hue / 254, value.Saturation / 254, 1)
            self.color_rgb = int(r * 255) << 16 | int(g * 255) << 8 | int(b * 255)
        except Exception as e:
            print(f"Error setting color: {e}")
            return

        print("update attributes")
        self._color_control.color_mode = color_control.ColorMode.HUE_SATURATION
        self._color_control.current_hue = value.Hue
        self._color_control.current_saturation = value.Saturation
