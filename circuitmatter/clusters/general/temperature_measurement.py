from circuitmatter import data_model
from circuitmatter import tlv


'''
  static var CLUSTERS  = matter.consolidate_clusters(_class, {
    0x0402: [0,1,2],                                # Temperature Measurement p.97 - no writable
  })
  static var TYPES = { 0x0302: 2 }                  # Temperature Sensor, rev 2
'''
class TemperatureMeasurement(data_model.Cluster):
    CLUSTER_ID = 0x0402

  '''
    # ====================================================================================================
    if   cluster == 0x0402              # ========== Temperature Measurement 2.3 p.97 ==========
      if   attribute == 0x0000          #  ---------- MeasuredValue / i16 (*100) ----------
        return tlv_solo.set_or_nil(TLV.I2, self.shadow_value)
      elif attribute == 0x0001          #  ---------- MinMeasuredValue / i16 (*100) ----------
        return tlv_solo.set(TLV.I2, -5000)  # -50 °C
      elif attribute == 0x0002          #  ---------- MaxMeasuredValue / i16 (*100) ----------
        return tlv_solo.set(TLV.I2, 15000)  # 150 °C
      end
  '''
    MeasuredValue = data_model.NumberAttribute(0x0000, signed=True, bits=16, default=0)
    MinMeasuredValue = data_model.NumberAttribute(0x0001, signed=True, bits=16, default=-5000)
    MaxMeasuredValue = data_model.NumberAttribute(0x0002, signed=True, bits=16, default=15000)
