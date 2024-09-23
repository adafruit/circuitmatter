import math
from typing import Optional

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typing_extensions import assert_type

from circuitmatter import tlv

# Test TLV encoding using examples from spec

# Type and Value
#  Encoding (hex)
# Boolean false
#  08
# Boolean true
#  09


class Bool(tlv.Structure):
    b = tlv.BoolMember(0)


class TestBool:
    def test_bool_false_decode(self):
        s, _ = Bool.decode(0x15, b"\x28\x00\x18")
        assert str(s) == "{\n  b = false\n}"
        assert s.b is False

    def test_bool_true_decode(self):
        s, _ = Bool.decode(0x15, b"\x29\x00\x18")
        assert str(s) == "{\n  b = true\n}"
        assert s.b is True

    def test_bool_false_encode(self):
        s = Bool()
        s.b = False
        assert s.encode().tobytes() == b"\x15\x28\x00\x18"

    def test_bool_true_encode(self):
        s = Bool()
        s.b = True
        assert s.encode().tobytes() == b"\x15\x29\x00\x18"


class SignedIntOneOctet(tlv.Structure):
    i = tlv.NumberMember(0, "b")


class SignedIntTwoOctet(tlv.Structure):
    i = tlv.NumberMember(0, "h")


class SignedIntFourOctet(tlv.Structure):
    i = tlv.NumberMember(0, "i")


class SignedIntEightOctet(tlv.Structure):
    i = tlv.NumberMember(0, "q")


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
        s, _ = SignedIntOneOctet.decode(0x15, b"\x20\x00\x2a")
        assert str(s) == "{\n  i = 42\n}"
        assert s.i == 42

    def test_signed_int_negative_17_decode(self):
        s, _ = SignedIntOneOctet.decode(0x15, b"\x20\x00\xef")
        assert str(s) == "{\n  i = -17\n}"
        assert s.i == -17

    def test_signed_int_42_two_octet_decode(self):
        s, _ = SignedIntTwoOctet.decode(0x15, b"\x21\x00\x2a\x00")
        assert str(s) == "{\n  i = 42\n}"
        assert s.i == 42

    def test_signed_int_negative_170000_decode(self):
        s, _ = SignedIntFourOctet.decode(0x15, b"\x22\x00\xf0\x67\xfd\xff")
        assert str(s) == "{\n  i = -170000\n}"
        assert s.i == -170000

    def test_signed_int_40000000000_decode(self):
        s, _ = SignedIntEightOctet.decode(
            0x15, b"\x23\x00\x00\x90\x2f\x50\x09\x00\x00\x00"
        )
        assert str(s) == "{\n  i = 40000000000\n}"
        assert s.i == 40000000000

    def test_signed_int_42_encode(self):
        s = SignedIntOneOctet()
        s.i = 42
        assert s.encode().tobytes() == b"\x15\x20\x00\x2a\x18"

    def test_signed_int_negative_17_encode(self):
        s = SignedIntOneOctet()
        s.i = -17
        assert s.encode().tobytes() == b"\x15\x20\x00\xef\x18"

    def test_signed_int_42_two_octet_encode(self):
        s = SignedIntTwoOctet()
        s.i = 42
        assert s.encode().tobytes() == b"\x15\x21\x00\x2a\x00\x18"

    def test_signed_int_negative_170000_encode(self):
        s = SignedIntFourOctet()
        s.i = -170000
        assert s.encode().tobytes() == b"\x15\x22\x00\xf0\x67\xfd\xff\x18"

    def test_signed_int_40000000000_encode(self):
        s = SignedIntEightOctet()
        s.i = 40000000000
        assert (
            s.encode().tobytes() == b"\x15\x23\x00\x00\x90\x2f\x50\x09\x00\x00\x00\x18"
        )

    @pytest.mark.parametrize(
        "octets,lower,upper",
        [
            (1, -128, 127),
            (2, -32_768, 32_767),
            (4, -2_147_483_648, 2_147_483_647),
            (8, -9_223_372_036_854_775_808, 9_223_372_036_854_775_807),
        ],
    )
    def test_bounds_checks(self, octets, lower, upper):
        class SignedIntStruct(tlv.Structure):
            i = tlv.IntMember(None, signed=True, octets=octets)

        s = SignedIntStruct()

        with pytest.raises(ValueError):
            s.i = lower - 1

        with pytest.raises(ValueError):
            s.i = upper + 1

        s.i = lower
        s.i = upper


class UnsignedIntOneOctet(tlv.Structure):
    i = tlv.NumberMember(0, "B")


# Unsigned Integer, 1-octet, value 42U
#  04 2a
class TestUnsignedInt:
    def test_unsigned_int_42_decode(self):
        s, _ = UnsignedIntOneOctet.decode(0x15, b"\x24\x00\x2a\x18")
        assert str(s) == "{\n  i = 42U\n}"
        assert s.i == 42

    def test_unsigned_int_42_encode(self):
        s = UnsignedIntOneOctet()
        s.i = 42
        assert s.encode().tobytes() == b"\x15\x24\x00\x2a\x18"

    @pytest.mark.parametrize(
        "octets,lower,upper",
        [
            (1, 0, 255),
            (2, 0, 65_535),
            (4, 0, 4_294_967_295),
            (8, 0, 18_446_744_073_709_551_615),
        ],
    )
    def test_bounds_checks(self, octets, lower, upper):
        class UnsignedIntStruct(tlv.Structure):
            i = tlv.IntMember(None, signed=False, octets=octets)

        s = UnsignedIntStruct()

        with pytest.raises(ValueError):
            s.i = lower - 1

        with pytest.raises(ValueError):
            s.i = upper + 1

        s.i = lower
        s.i = upper

    @given(v=st.integers(min_value=0, max_value=255))
    def test_roundtrip(self, v: int):
        s = UnsignedIntOneOctet()
        s.i = v
        buffer = s.encode().tobytes()

        s2, _ = UnsignedIntOneOctet.decode(0x15, buffer[1:])

        assert s2.i == s.i
        assert str(s2) == str(s)

    def test_nullability(self):
        class Struct(tlv.Structure):
            i = tlv.IntMember(None)
            ni = tlv.IntMember(None, nullable=True)

        s = Struct()
        assert_type(s.i, int)
        assert_type(s.ni, Optional[int])

        s.ni = None
        assert s.ni is None

        with pytest.raises(ValueError):
            s.i = None


# UTF-8 String, 1-octet length, "Hello!"
#  0c 06 48 65 6c 6c 6f 21
# UTF-8 String, 1-octet length, "Tschüs"
#  0c 07 54 73 63 68 c3 bc 73
class UTF8StringOneOctet(tlv.Structure):
    s = tlv.UTF8StringMember(0, 16)


class TestUTF8String:
    def test_utf8_string_hello_decode(self):
        s, _ = UTF8StringOneOctet.decode(0x15, b"\x2c\x00\x06Hello!")
        assert str(s) == '{\n  s = "Hello!"\n}'
        assert s.s == "Hello!"

    def test_utf8_string_tschs_decode(self):
        s, _ = UTF8StringOneOctet.decode(0x15, b"\x2c\x00\x07Tsch\xc3\xbcs")
        assert str(s) == '{\n  s = "Tschüs"\n}'
        assert s.s == "Tschüs"

    def test_utf8_string_hello_encode(self):
        s = UTF8StringOneOctet()
        s.s = "Hello!"
        assert s.encode().tobytes() == b"\x15\x2c\x00\x06Hello!\x18"

    def test_utf8_string_tschs_encode(self):
        s = UTF8StringOneOctet()
        s.s = "Tschüs"
        assert s.encode().tobytes() == b"\x15\x2c\x00\x07Tsch\xc3\xbcs\x18"

    @given(v=st.text(max_size=4))
    def test_roundtrip(self, v: str):
        s = UTF8StringOneOctet()
        print(len(v))
        s.s = v
        buffer = s.encode().tobytes()

        s2, _ = UTF8StringOneOctet.decode(0x15, buffer[1:])

        assert s2.s == s.s
        assert str(s2) == str(s)


# Octet String, 1-octet length, octets 00 01 02 03 04
# encoded: 10 05 00 01 02 03 04
class OctetStringOneOctet(tlv.Structure):
    s = tlv.OctetStringMember(0, 16)


class TestOctetString:
    def test_octet_string_decode(self):
        s, _ = OctetStringOneOctet.decode(0x15, b"\x30\x00\x05\x00\x01\x02\x03\x04\x18")
        assert str(s) == "{\n  s = 00 01 02 03 04\n}"
        assert s.s == b"\x00\x01\x02\x03\x04"

    def test_octet_string_encode(self):
        s = OctetStringOneOctet()
        s.s = b"\x00\x01\x02\x03\x04"
        assert s.encode().tobytes() == b"\x15\x30\x00\x05\x00\x01\x02\x03\x04\x18"

    @given(v=st.binary(max_size=16))
    def test_roundtrip(self, v: bytes):
        s = OctetStringOneOctet()
        s.s = v
        buffer = s.encode().tobytes()

        s2, _ = OctetStringOneOctet.decode(0x15, buffer[1:])

        assert s2.s == s.s
        assert str(s2) == str(s)


# Null
#  14


class Null(tlv.Structure):
    n = tlv.BoolMember(0, nullable=True)


class NotNull(tlv.Structure):
    n = tlv.BoolMember(0, nullable=True)
    b = tlv.BoolMember(1)


class TestNull:
    def test_null_decode(self):
        s, _ = Null.decode(0x15, b"\x34\x00\x18")
        assert str(s) == "{\n  n = null\n}"
        assert s.n is None

    def test_null_encode(self):
        s = Null()
        s.n = None
        assert s.encode().tobytes() == b"\x15\x34\x00\x18"

    def test_nullable(self):
        s = NotNull()

        assert_type(s.b, bool)
        with pytest.raises(ValueError):
            s.b = None  # type: ignore  # testing runtime behaviour


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
class FloatSingle(tlv.Structure):
    f = tlv.FloatMember(0)


class FloatDouble(tlv.Structure):
    f = tlv.FloatMember(0, octets=8)


class TestFloatSingle:
    def test_precision_float_0_0_decode(self):
        s, _ = FloatSingle.decode(0x15, b"\x2a\x00\x00\x00\x00\x00\x18")
        assert str(s) == "{\n  f = 0.0\n}"
        assert s.f == 0.0

    def test_precision_float_1_3_decode(self):
        s, _ = FloatSingle.decode(0x15, b"\x2a\x00\xab\xaa\xaa\x3e\x18")
        # assert str(s) == "{\n  f = 0.3333333432674408\n}"
        f = s.f
        assert math.isclose(f, 1.0 / 3.0, rel_tol=1e-06)

    def test_precision_float_17_9_decode(self):
        s, _ = FloatSingle.decode(0x15, b"\x2a\x00\x33\x33\x8f\x41\x18")
        assert str(s) == "{\n  f = 17.899999618530273\n}"
        assert math.isclose(s.f, 17.9, rel_tol=1e-06)

    def test_precision_float_infinity_decode(self):
        s, _ = FloatSingle.decode(0x15, b"\x2a\x00\x00\x00\x80\x7f\x18")
        assert str(s) == "{\n  f = inf\n}"
        assert math.isinf(s.f)

    def test_precision_float_negative_infinity_decode(self):
        s, _ = FloatSingle.decode(0x15, b"\x2a\x00\x00\x00\x80\xff\x18")
        assert str(s) == "{\n  f = -inf\n}"
        assert math.isinf(s.f)

    def test_precision_float_0_0_encode(self):
        s = FloatSingle()
        s.f = 0.0
        assert s.encode().tobytes() == b"\x15\x2a\x00\x00\x00\x00\x00\x18"

    def test_precision_float_1_3_encode(self):
        s = FloatSingle()
        s.f = 1.0 / 3.0
        assert s.encode().tobytes() == b"\x15\x2a\x00\xab\xaa\xaa\x3e\x18"

    def test_precision_float_17_9_encode(self):
        s = FloatSingle()
        s.f = 17.9
        assert s.encode().tobytes() == b"\x15\x2a\x00\x33\x33\x8f\x41\x18"

    def test_precision_float_infinity_encode(self):
        s = FloatSingle()
        s.f = float("inf")
        assert s.encode().tobytes() == b"\x15\x2a\x00\x00\x00\x80\x7f\x18"

    def test_precision_float_negative_infinity_encode(self):
        s = FloatSingle()
        s.f = float("-inf")
        assert s.encode().tobytes() == b"\x15\x2a\x00\x00\x00\x80\xff\x18"

    @given(v=...)
    def test_roundtrip_double(self, v: float):
        s = FloatDouble()
        s.f = v
        buffer = s.encode().tobytes()

        s2, _ = FloatDouble.decode(0x15, buffer[1:])

        assert (
            (math.isnan(s.f) and math.isnan(s2.f))
            or (s.f > 3.4028235e38 and s2.f == float("inf"))
            or (s.f < -3.4028235e38 and s2.f == float("-inf"))
            or math.isclose(s2.f, s.f, rel_tol=1e-7, abs_tol=1e-9)
        )

    @given(
        v=st.floats(
            # encoding to LE float32 raises OverflowError outside these ranges
            # TODO: should we raise ValueError with a bounds check or encode -inf/inf?
            min_value=(2**-126),
            max_value=(2 - 2**-23) * 2**127,
        ),
    )
    def test_roundtrip_single(self, v: float):
        s = FloatSingle()
        s.f = v
        buffer = s.encode().tobytes()
        print("Buffer", buffer.hex(" "))

        s2, _ = FloatSingle.decode(0x15, buffer[1:])

        assert (math.isnan(s.f) and math.isnan(s2.f)) or math.isclose(
            s2.f, s.f, rel_tol=1e-7, abs_tol=1e-9
        )


class TestFloatDouble:
    def test_precision_float_0_0_decode(self):
        s, _ = FloatDouble.decode(0x15, b"\x2b\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        assert str(s) == "{\n  f = 0.0\n}"
        assert s.f == 0.0

    def test_precision_float_1_3_decode(self):
        s, _ = FloatDouble.decode(0x15, b"\x2b\x00\x55\x55\x55\x55\x55\x55\xd5\x3f")
        # assert str(s) == "{\n  f = 0.3333333333333333\n}"
        f = s.f
        assert math.isclose(f, 1.0 / 3.0, rel_tol=1e-06)

    def test_precision_float_17_9_decode(self):
        s, _ = FloatDouble.decode(0x15, b"\x2b\x00\x66\x66\x66\x66\x66\xe6\x31\x40")
        assert str(s) == "{\n  f = 17.9\n}"
        assert math.isclose(s.f, 17.9, rel_tol=1e-06)

    def test_precision_float_infinity_decode(self):
        s, _ = FloatDouble.decode(0x15, b"\x2b\x00\x00\x00\x00\x00\x00\x00\xf0\x7f")
        assert str(s) == "{\n  f = inf\n}"
        assert math.isinf(s.f)

    def test_precision_float_negative_infinity_decode(self):
        s, _ = FloatDouble.decode(0x15, b"\x2b\x00\x00\x00\x00\x00\x00\x00\xf0\xff")
        assert str(s) == "{\n  f = -inf\n}"
        assert math.isinf(s.f)

    def test_precision_float_0_0_encode(self):
        s = FloatDouble()
        s.f = 0.0
        assert (
            s.encode().tobytes() == b"\x15\x2b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18"
        )

    def test_precision_float_1_3_encode(self):
        s = FloatDouble()
        s.f = 1.0 / 3.0
        assert (
            s.encode().tobytes() == b"\x15\x2b\x00\x55\x55\x55\x55\x55\x55\xd5\x3f\x18"
        )

    def test_precision_float_17_9_encode(self):
        s = FloatDouble()
        s.f = 17.9
        assert (
            s.encode().tobytes() == b"\x15\x2b\x00\x66\x66\x66\x66\x66\xe6\x31\x40\x18"
        )

    def test_precision_float_infinity_encode(self):
        s = FloatDouble()
        s.f = float("inf")
        assert (
            s.encode().tobytes() == b"\x15\x2b\x00\x00\x00\x00\x00\x00\x00\xf0\x7f\x18"
        )

    def test_precision_float_negative_infinity_encode(self):
        s = FloatDouble()
        s.f = float("-inf")
        assert (
            s.encode().tobytes() == b"\x15\x2b\x00\x00\x00\x00\x00\x00\x00\xf0\xff\x18"
        )

    @given(v=...)
    def test_roundtrip(self, v: float):
        s = FloatDouble()
        s.f = v
        buffer = s.encode().tobytes()

        s2, _ = FloatDouble.decode(0x15, buffer[1:])

        assert (
            (math.isnan(s.f) and math.isnan(s2.f))
            or (s.f > 1.8e308 and s2.f == float("inf"))
            or (s.f < -1.8e308 and s2.f == float("-inf"))
            or math.isclose(s2.f, s.f, rel_tol=2.22e-16, abs_tol=1e-15)
        )


class InnerStruct(tlv.Structure):
    a = tlv.IntMember(0, signed=True, optional=True, octets=4)
    b = tlv.IntMember(1, signed=True, optional=True, octets=4)


class OuterStruct(tlv.Structure):
    s = tlv.StructMember(0, InnerStruct)


class TestStruct:
    def test_inner_struct_decode(self):
        s, _ = OuterStruct.decode(0x15, b"\x35\x00\x20\x00\x2a\x20\x01\xef\x18\x18")
        assert_type(s, OuterStruct)
        assert_type(s.s, InnerStruct)
        assert_type(s.s.a, Optional[int])
        assert str(s) == "{\n  s = {\n    a = 42,\n    b = -17\n  }\n}"
        assert s.s.a == 42
        assert s.s.b == -17

    def test_inner_struct_decode_empty(self):
        s, _ = OuterStruct.decode(0x15, b"\x35\x00\x18\x18")
        assert str(s) == "{\n  s = {\n    \n  }\n}"
        assert s.s.a is None
        assert s.s.b is None

    def test_inner_struct_encode(self):
        s = OuterStruct()
        inner = InnerStruct()
        inner.a = 42
        inner.b = -17
        s.s = inner
        assert (
            s.encode().tobytes()
            == b"\x15\x35\x00\x22\x00\x2a\x00\x00\x00\x22\x01\xef\xff\xff\xff\x18\x18"
        )

    def test_inner_struct_encode_empty(self):
        s = OuterStruct()
        s.s = InnerStruct()
        assert s.encode().tobytes() == b"\x15\x35\x00\x18\x18"


class FullyQualified(tlv.Structure):
    a = tlv.IntMember((0xADA, 0xF00, 0x123), signed=True, optional=True, octets=4)
    b = tlv.IntMember((0xADA, 0xF00, 0x12345), signed=True, optional=True, octets=4)


class TestFullyQualifiedTags:
    def test_decode(self):
        s, _ = FullyQualified.decode(
            0x15,
            b"\xc2\xda\x0a\x00\x0f\x23\x01\x2a\x00\x00\x00\xe2\xda\x0a\x00\x0f\x45\x23\x01\x00\xef\xff\xff\xff\x18",
        )
        assert_type(s, FullyQualified)
        assert_type(s.a, Optional[int])
        assert str(s) == "{\n  a = 42,\n  b = -17\n}"
        assert s.a == 42
        assert s.b == -17

    def test_encode(self):
        s = FullyQualified()
        s.a = 42
        s.b = -17
        assert (
            s.encode().tobytes()
            == b"\x15\xc2\xda\x0a\x00\x0f\x23\x01\x2a\x00\x00\x00\xe2\xda\x0a\x00\x0f\x45\x23\x01\x00\xef\xff\xff\xff\x18"
        )


class InnerList(tlv.List):
    a = tlv.IntMember(0, signed=True, optional=True, octets=4)
    b = tlv.IntMember(1, signed=True, optional=True, octets=4)


class OuterStructList(tlv.Structure):
    sublist = tlv.ListMember(0, InnerList)


class TestList:
    def test_encode(self):
        s = OuterStructList()
        inner = InnerList()
        inner.a = 42
        inner.b = -17
        s.sublist = inner
        assert (
            s.encode().tobytes()
            == b"\x15\x37\x00\x22\x00\x2a\x00\x00\x00\x22\x01\xef\xff\xff\xff\x18\x18"
        )


class OuterStructArray(tlv.Structure):
    a = tlv.ArrayMember(0, InnerList)


class TestArray:
    def test_encode(self):
        s = OuterStructArray()
        inner = InnerList()
        inner.a = 42
        inner.b = -17
        s.a = [inner]
        assert (
            s.encode().tobytes()
            == b"\x15\x36\x00\x17\x22\x00\x2a\x00\x00\x00\x22\x01\xef\xff\xff\xff\x18\x18\x18"
        )

    def test_encode2(self):
        s = OuterStructArray()
        inner = InnerList()
        inner.a = 42
        inner.b = -17
        s.a = [inner, inner]
        assert (
            s.encode().tobytes()
            == b"\x15\x36\x00\x17\x22\x00\x2a\x00\x00\x00\x22\x01\xef\xff\xff\xff\x18\x17\x22\x00\x2a\x00\x00\x00\x22\x01\xef\xff\xff\xff\x18\x18\x18"
        )
