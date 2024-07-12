from circuitmatter import tlv

# Test TLV encoding using examples from spec

# Type and Value
#  Encoding (hex)
# Boolean false
#  08

class Bool(tlv.TLVStructure):
    b = tlv.BoolMember(None)

class TestBoolFalse:
    def test_bool_false_decode(self):
        s = Bool(b"\x08")
        assert str(s) == "{\n  b = false\n}"
        assert not s.b

    def test_bool_false_encode(self):
        s = Bool()
        s.b = False
        assert bytes(s) == b"\x08"

# Boolean true
#  09
# Signed Integer, 1-octet, value 42
#  00 2a
# Signed Integer, 1-octet, value -17
#  00 ef
# Unsigned Integer, 1-octet, value 42U
#  04 2a
# Signed Integer, 2-octet, value 42
#  01 2a 00
# Signed Integer, 4-octet, value -170000
#  02 f0 67 fd ff
# Signed Integer, 8-octet, value 40000000000
#  03 00 90 2f 50 09 00 00 00
# UTF-8 String, 1-octet length, "Hello!"
#  0c 06 48 65 6c 6c 6f 21
# UTF-8 String, 1-octet length, "Tschüs"
#  0c 07 54 73 63 68 c3 bc 73
# Octet String, 1-octet length, octets 00 01 02 03 04 10 05 00 01 02 03 04
# Null
#  14
# Single precision floating point 0.0
#  0a 00 00 00 00
# Single precision floating point (1.0 / 3.0)
#  0a ab aa aa 3e
# Single precision floating point 17.9
#  0a 33 33 8f 41
# Single precision floating point infinity (∞)
#  0a 00 00 80 7f
# Single precision floating point negative infinity
#  0a 00 00 80 ff
# (-∞)
# Double precision floating point 0.0
#  0b 00 00 00 00 00 00 00 00
# Double precision floating point (1.0 / 3.0)
#  0b 55 55 55 55 55 55 d5 3f
# Double precision floating point 17.9
#  0b 66 66 66 66 66 e6 31 40
# Double precision floating point infinity (∞)
#  0b 00 00 00 00 00 00 f0 7f
# Double precision floating point negative infinity 0b 00 00 00 00 00 00 f0 ff
# (-∞)