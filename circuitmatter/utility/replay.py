import binascii


class ReplaySocket:
    def __init__(self, replay_data):
        self.replay_data = replay_data
        self._last_timestamp = 0

    def bind(self, address):
        print("bind to", address)

    def setblocking(self, value):
        print("setblocking", value)

    def recvfrom_into(self, buffer, nbytes=None):
        if nbytes is None:
            nbytes = len(buffer)
        next_timestamp = self.replay_data[0][1]
        if next_timestamp - self._last_timestamp > 1000000:
            self._last_timestamp = next_timestamp
            raise BlockingIOError()
        direction = "send"
        while direction == "send":
            direction, timestamp, address, data_b64 = self.replay_data.pop(0)

        decoded = binascii.a2b_base64(data_b64)
        if len(decoded) > nbytes:
            raise RuntimeError("Next replay packet is larger than buffer to read into")
        buffer[: len(decoded)] = decoded
        self._last_timestamp = timestamp
        return len(decoded), address

    def sendto(self, data, address):
        if address is None:
            raise ValueError("Address must be set")
        # direction, _, address, data_b64 = self.replay_data.pop(0)
        # if direction == "send":
        #     decoded = binascii.a2b_base64(data_b64)
        # for i, b in enumerate(data):
        #     if b != decoded[i]:
        #         # print("sent", data.hex(" "))
        #         # print("old ", decoded.hex(" "))
        #         # print(i, hex(b), hex(decoded[i]))
        #         print("Next replay packet does not match sent data")
        return len(data)


class ReplayRandom:
    def __init__(self, replay_data):
        self.replay_data = replay_data

    def urandom(self, nbytes):
        direction = None
        while direction != "urandom":
            direction, _, recorded_nbytes, data_b64 = self.replay_data.pop(0)
            if recorded_nbytes != nbytes:
                raise RuntimeError("Next replay random data is not the expected length")
        decoded = binascii.a2b_base64(data_b64)
        return decoded

    def randbelow(self, n):
        direction = None
        while direction != "randbelow":
            direction, _, recorded_n, value = self.replay_data.pop(0)
            if recorded_n != n:
                raise RuntimeError("Next replay randbelow is not the expected length")
        return value


class ReplaySocketPool:
    AF_INET6 = 0
    SOCK_DGRAM = 1

    def __init__(self, replay_lines):
        self.replay_data = replay_lines
        self._socket_created = False

    def socket(self, *args, **kwargs):
        if self._socket_created:
            raise RuntimeError("Only one socket can be created")
        self._socket_created = True
        return ReplaySocket(self.replay_data)
