from .on_off import OnOffLight


class DimmableLight(OnOffLight):
    DEVICE_TYPE_ID = 0x0101
