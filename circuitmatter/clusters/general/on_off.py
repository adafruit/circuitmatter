from circuitmatter import data_model
from circuitmatter import tlv


class StartUpOnOffEnum(data_model.Enum8):
    OFF = 0
    ON = 1
    TOGGLE = 2


class OnOff(data_model.Cluster):
    CLUSTER_ID = 0x0006

    OnOff = data_model.BoolAttribute(0x0000, default=False)
    GlobalSceneControl = data_model.BoolAttribute(0x4000, default=True)
    OnTime = data_model.NumberAttribute(0x4001, signed=False, bits=16, default=0)
    OffWaitTime = data_model.NumberAttribute(0x4002, signed=False, bits=16, default=0)
    StartUpOnOff = data_model.EnumAttribute(0x4003, StartUpOnOffEnum)

    off = data_model.Command(0x00, None)
    on = data_model.Command(0x01, None)
    toggle = data_model.Command(0x02, None)

    class OffWithEffect(tlv.Structure):
        EffectIdentifier = tlv.EnumMember(0, 0)
        EffectVariant = tlv.EnumMember(1, 0, default=0)

    off_with_effect = data_model.Command(0x40, OffWithEffect)
    on_with_recall_global_scene = data_model.Command(0x41, None)
    on_with_timed_off = data_model.Command(0x42, None)
