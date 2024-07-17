"""Pure Python implementation of the Matter IOT protocol."""

import os

import circuitmatter as cm


# descriminator = 3840
# avahi = subprocess.Popen(["avahi-publish-service", "-v", f"--subtype=_L{descriminator}._sub._matterc._udp", "--subtype=_CM._sub._matterc._udp", "FA93546B21F5FB54", "_matterc._udp", "5540", "PI=", "PH=33", "CM=1", f"D={descriminator}", "CRI=3000", "CRA=4000", "T=1", "VP=65521+32769"])

# # Define the UDP IP address and port
# UDP_IP = "::"  # Listen on all available network interfaces
# UDP_PORT = 5540

# # Create the UDP socket
# sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

# # Bind the socket to the IP and port
# sock.bind((UDP_IP, UDP_PORT))

# print(f"Listening on UDP port {UDP_PORT}")

unsecured_session_context = {}
secure_session_contexts = ["reserved"]

# while True:
#     # Receive data from the socket (1280 is the minimum ipv6 MTU and the max UDP matter packet size.)
#     data, addr = sock.recvfrom(1280)
data = b"\x04\x00\x00\x00\x0b\x06\xb7\t)\xad\x07\xd9\xae\xa1\xee\xa0\x05 j\x15\x00\x00\x150\x01 \x97\x064#\x1c\xd1E7H\x0b|\xc2G\xa7\xc38\xe9\xce3\x11\xb2@M\x86\xd7\xb5{)\xaa`\xddb%\x02\xc2\x86$\x03\x00(\x045\x05%\x01\xf4\x01%\x02,\x01%\x03\xa0\x0f$\x04\x11$\x05\x0b&\x06\x00\x00\x03\x01$\x07\x01\x18\x18"
addr = None


# pathlib.Path("data.bin").write_bytes(data)

bookmarks = []


def add_bookmark(start, length, name, color=0x0000FF):
    bookmarks.append(
        {
            "color": 0x4F000000 | color,
            "comment": "\n",
            "id": len(bookmarks),
            "locked": True,
            "name": name,
            "region": {"address": start, "size": length},
        }
    )
    # Write every time in case we crash
    # pathlib.Path("parsed.hexbm").write_text(json.dumps({"bookmarks": bookmarks}))


def run():
    manager = cm.SessionManager()
    # Print the received data and the address of the sender
    # This is section 4.7.2
    print(f"Received packet from {addr}: {data}")
    message = cm.Message(data)
    if message.secure_session:
        # Decrypt the payload
        pass
    if not manager.counter_ok(message):
        print("Dropping message due to counter error")
        return
    # if not manager.rmp_ok(message):
    #     print("Dropping message due to RMP")
    #     continue

    protocol_id = message.protocol_id
    protocol_opcode = message.protocol_opcode

    if protocol_id == cm.ProtocolId.SECURE_CHANNEL:
        if protocol_opcode == cm.SecureProtocolOpcode.MSG_COUNTER_SYNC_REQ:
            print("Received Message Counter Synchronization Request")
        elif protocol_opcode == cm.SecureProtocolOpcode.MSG_COUNTER_SYNC_RSP:
            print("Received Message Counter Synchronization Response")
        elif protocol_opcode == cm.SecureProtocolOpcode.PBKDF_PARAM_REQUEST:
            print("Received PBKDF Parameter Request")
            # This is Section 4.14.1.2
            request = cm.PBKDFParamRequest(message.payload)
            if request.passcodeID == 0:
                pass
                # Send back failure
                # response = StatusReport()
                # response.GeneralCode
            print(request)
            response = cm.PBKDFParamResponse()
            response.initiatorRandom = request.initiatorRandom

            # Generate a random number
            response.responderRandom = os.urandom(32)
            session_context = manager.new_context(response.responderSessionId)

            session_context.peer_session_id = request.initiatorSessionId
            if not request.hasPBKDFParameters:
                params = cm.Crypto_PBKDFParameterSet()
                params.iterations = 1000
                params.salt = b"\x00" * 32
                response.pbkdf_parameters = params
            print(response)

        elif protocol_opcode == cm.SecureProtocolOpcode.PBKDF_PARAM_RESPONSE:
            print("Received PBKDF Parameter Response")
        elif protocol_opcode == cm.SecureProtocolOpcode.PASE_PAKE1:
            print("Received PASE PAKE1")
        elif protocol_opcode == cm.SecureProtocolOpcode.PASE_PAKE2:
            print("Received PASE PAKE2")
        elif protocol_opcode == cm.SecureProtocolOpcode.PASE_PAKE3:
            print("Received PASE PAKE3")
        elif protocol_opcode == cm.SecureProtocolOpcode.CASE_SIGMA1:
            print("Received CASE Sigma1")
        elif protocol_opcode == cm.SecureProtocolOpcode.CASE_SIGMA2:
            print("Received CASE Sigma2")
        elif protocol_opcode == cm.SecureProtocolOpcode.CASE_SIGMA3:
            print("Received CASE Sigma3")
        elif protocol_opcode == cm.SecureProtocolOpcode.CASE_SIGMA2_RESUME:
            print("Received CASE Sigma2 Resume")
        elif protocol_opcode == cm.SecureProtocolOpcode.STATUS_REPORT:
            print("Received Status Report")
        elif protocol_opcode == cm.SecureProtocolOpcode.ICD_CHECK_IN:
            print("Received ICD Check-in")

    # avahi.kill()


if __name__ == "__main__":
    run()
