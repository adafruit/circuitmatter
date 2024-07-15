from circuitmatter import tlv

import math

# Test TLV encoding using examples from spec

# Type and Value
#  Encoding (hex)
# Boolean false
#  08
# Boolean true
#  09


class Bool(tlv.TLVStructure):
    b = tlv.BoolMember(None)


class TestBool:
    def test_bool_false_decode(self):
        s = Bool(b"\x08")
        assert str(s) == "{\n  b = false\n}"
        assert not s.b

    def test_bool_true_decode(self):
        s = Bool(b"\x09")
        assert str(s) == "{\n  b = true\n}"
        assert s.b

    # def test_bool_false_encode(self):
    #     s = Bool()
    #     s.b = False
    #     assert bytes(s) == b"\x08"


class SignedIntOneOctet(tlv.TLVStructure):
    i = tlv.IntegerMember(None, "b")


class SignedIntTwoOctet(tlv.TLVStructure):
    i = tlv.IntegerMember(None, "h")


class SignedIntFourOctet(tlv.TLVStructure):
    i = tlv.IntegerMember(None, "i")


class SignedIntEightOctet(tlv.TLVStructure):
    i = tlv.IntegerMember(None, "q")


# Signed Integer, 1-octet, value 42
#  00 2a
# Signed Integer, 1-octet, value -17
#  00 ef
# Signed Integer, 2-octet, value 42
#  01 2a 00
# Signed Integer, 4-octet, value -170000
#  02 f0 67 fd ff
# Signed Integer, 8-octet, value 40000000000
#  03 00 90 2f 50 09 00 00 00
class TestSignedInt:
    def test_signed_int_42_decode(self):
        s = SignedIntOneOctet(b"\x00\x2a")
        assert str(s) == "{\n  i = 42\n}"
        assert s.i == 42

    def test_signed_int_negative_17_decode(self):
        s = SignedIntOneOctet(b"\x00\xef")
        assert str(s) == "{\n  i = -17\n}"
        assert s.i == -17

    # def test_signed_int_42_encode(self):
    #     s = SignedInt()
    #     s.i = 42
    #     assert bytes(s) == b"\x00\x2a"

    def test_signed_int_42_two_octet_decode(self):
        s = SignedIntTwoOctet(b"\x01\x2a\x00")
        assert str(s) == "{\n  i = 42\n}"
        assert s.i == 42

    def test_signed_int_negative_170000_decode(self):
        s = SignedIntFourOctet(b"\x02\xf0\x67\xfd\xff")
        assert str(s) == "{\n  i = -170000\n}"
        assert s.i == -170000

    def test_signed_int_40000000000_decode(self):
        s = SignedIntEightOctet(b"\x03\x00\x90\x2f\x50\x09\x00\x00\x00")
        assert str(s) == "{\n  i = 40000000000\n}"
        assert s.i == 40000000000


class UnsignedIntOneOctet(tlv.TLVStructure):
    i = tlv.IntegerMember(None, "B")


# Unsigned Integer, 1-octet, value 42U
#  04 2a
class TestUnsignedInt:
    def test_unsigned_int_42_decode(self):
        s = UnsignedIntOneOctet(b"\x00\x2a")
        assert str(s) == "{\n  i = 42U\n}"
        assert s.i == 42

    # def test_unsigned_int_42_encode(self):
    #     s = UnsignedInt()
    #     s.i = 42
    #     assert bytes(s) == b"\x00\x2a"


# UTF-8 String, 1-octet length, "Hello!"
#  0c 06 48 65 6c 6c 6f 21
# UTF-8 String, 1-octet length, "Tschüs"
#  0c 07 54 73 63 68 c3 bc 73
class UTF8StringOneOctet(tlv.TLVStructure):
    s = tlv.UTF8StringMember(None, 16)


class TestUTF8String:
    def test_utf8_string_hello_decode(self):
        s = UTF8StringOneOctet(b"\x0c\x06Hello!")
        assert str(s) == '{\n  s = "Hello!"\n}'
        assert s.s == "Hello!"

    def test_utf8_string_tschs_decode(self):
        s = UTF8StringOneOctet(b"\x0c\x07Tsch\xc3\xbcs")
        assert str(s) == '{\n  s = "Tschüs"\n}'
        assert s.s == "Tschüs"

    # def test_utf8_string_hello_encode(self):
    #     s = UTF8String()
    #     s.s = b"Hello!"
    #     assert bytes(s) == b"\x0c\x06Hello!"


# Octet String, 1-octet length, octets 00 01 02 03 04
# encoded: 10 05 00 01 02 03 04
class OctetStringOneOctet(tlv.TLVStructure):
    s = tlv.OctetStringMember(None, 16)


class TestOctetString:
    def test_octet_string_decode(self):
        s = OctetStringOneOctet(b"\x10\x05\x00\x01\x02\x03\x04")
        assert str(s) == "{\n  s = 00 01 02 03 04\n}"
        assert s.s == b"\x00\x01\x02\x03\x04"


# Null
#  14


class Null(tlv.TLVStructure):
    n = tlv.BoolMember(None, optional=True)


class TestNull:
    def test_null_decode(self):
        s = Null(b"\x14")
        assert str(s) == "{\n  n = null\n}"
        assert s.n is None

    # def test_null_encode(self):
    #     s = Null()
    #     s.n = None
    #     assert bytes(s) == b"\x14"


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
class Float(tlv.TLVStructure):
    f = tlv.FloatMember(None)


class TestFloat:
    def test_single_precision_float_0_0_decode(self):
        s = Float(b"\x0a\x00\x00\x00\x00")
        assert str(s) == "{\n  f = 0.0\n}"
        assert s.f == 0.0

    def test_single_precision_float_1_3_decode(self):
        s = Float(b"\x0a\xab\xaa\xaa\x3e")
        # assert str(s) == "{\n  f = 0.3333333432674408\n}"
        f = s.f
        assert math.isclose(f, 1.0 / 3.0, rel_tol=1e-06)

    def test_single_precision_float_17_9_decode(self):
        s = Float(b"\x0a\x33\x33\x8f\x41")
        assert str(s) == "{\n  f = 17.899999618530273\n}"
        assert math.isclose(s.f, 17.9, rel_tol=1e-06)

    def test_single_precision_float_infinity_decode(self):
        s = Float(b"\x0a\x00\x00\x80\x7f")
        assert str(s) == "{\n  f = inf\n}"
        assert math.isinf(s.f)

    def test_single_precision_float_negative_infinity_decode(self):
        s = Float(b"\x0a\x00\x00\x80\xff")
        assert str(s) == "{\n  f = -inf\n}"
        assert math.isinf(s.f)

    def test_double_precision_float_0_0_decode(self):
        s = Float(b"\x0b\x00\x00\x00\x00\x00\x00\x00\x00")
        assert str(s) == "{\n  f = 0.0\n}"
        assert s.f == 0.0

    def test_double_precision_float_1_3_decode(self):
        s = Float(b"\x0b\x55\x55\x55\x55\x55\x55\xd5\x3f")
        # assert str(s) == "{\n  f = 0.3333333333333333\n}"
        f = s.f
        assert math.isclose(f, 1.0 / 3.0, rel_tol=1e-06)

    def test_double_precision_float_17_9_decode(self):
        s = Float(b"\x0b\x66\x66\x66\x66\x66\xe6\x31\x40")
        assert str(s) == "{\n  f = 17.9\n}"
        assert math.isclose(s.f, 17.9, rel_tol=1e-06)

    def test_double_precision_float_infinity_decode(self):
        s = Float(b"\x0b\x00\x00\x00\x00\x00\x00\xf0\x7f")
        assert str(s) == "{\n  f = inf\n}"
        assert math.isinf(s.f)

    def test_double_precision_float_negative_infinity_decode(self):
        s = Float(b"\x0b\x00\x00\x00\x00\x00\x00\xf0\xff")
        assert str(s) == "{\n  f = -inf\n}"
        assert math.isinf(s.f)

    # def test_single_precision_float_0_0_encode(self):
    #     s = SinglePrecisionFloat()
    #     s.f = 0.0
    #     assert bytes(s) == b"\x0a\x00\x00\x00\x00"
