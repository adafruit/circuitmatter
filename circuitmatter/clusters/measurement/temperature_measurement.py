from circuitmatter import data_model


class TemperatureMeasurement(data_model.Cluster):
    CLUSTER_ID = 0x0402
    REVISION = 4

    MeasuredValue = data_model.NumberAttribute(
        0x0000, signed=True, bits=16, default=0, X_nullable=True, P_reportable=True
    )
    MinMeasuredValue = data_model.NumberAttribute(
        0x0001, signed=True, bits=16, default=-5000, X_nullable=True
    )
    MaxMeasuredValue = data_model.NumberAttribute(
        0x0002, signed=True, bits=16, default=15000, X_nullable=True
    )
