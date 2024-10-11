from circuitmatter import interaction_model
from circuitmatter import tlv


class Message(interaction_model.ChunkedMessage):
    Array = tlv.ArrayMember(0, tlv.IntMember(None, signed=False, octets=2))
    MoreChunkedMessages = tlv.BoolMember(1, optional=True)
    After = tlv.IntMember(2, signed=False, octets=4)


def fill_array(length):
    t = Message()
    t.Array = list(range(length))
    t.After = 0xADAF
    return t


def test_only_one():
    buf = bytearray(20)
    t = fill_array(4)
    end = t.encode_into(buf)
    print(buf[:end].hex("x"))
    assert (
        buf[:end]
        == b"\x15\x36\x00\x04\x00\x04\x01\x04\x02\x04\x03\x18\x25\x02\xaf\xad\x24\xff\x0b\x18"
    )


def test_two_chunks():
    buf = bytearray(16)
    t = fill_array(4)
    end = t.encode_into(buf)
    print(buf[:end].hex("x"))
    assert (
        buf[:end]
        == b"\x15\x36\x00\x04\x00\x04\x01\x04\x18\x25\x02\xaf\xad\x24\xff\x0b\x18"
    )


def test_two_chunks2():
    buf = bytearray(17)
    t = fill_array(4)
    end = t.encode_into(buf)
    print(buf[:end].hex("x"))
    assert (
        buf[:end]
        == b"\x15\x36\x00\x04\x00\x04\x01\x04\x18\x25\x02\xaf\xad\x24\xff\x0b\x18"
    )


def test_two_chunks_ok():
    buf = bytearray(18)
    t = fill_array(4)
    end = t.encode_into(buf)
    print(buf[:end].hex("x"))
    assert (
        buf[:end]
        == b"\x15\x36\x00\x04\x00\x04\x01\x04\x18\x25\x02\xaf\xad\x24\xff\x0b\x18"
    )


def test_three_chunks():
    pass
