from . import crypto
from . import session
from . import tlv


class Sigma1(tlv.Structure):
    initiatorRandom = tlv.OctetStringMember(1, 32)
    initiatorSessionId = tlv.IntMember(2, signed=False, octets=2)
    destinationId = tlv.OctetStringMember(3, crypto.HASH_LEN_BYTES)
    initiatorEphPubKey = tlv.OctetStringMember(4, crypto.PUBLIC_KEY_SIZE_BYTES)
    initiatorSessionParams = tlv.StructMember(
        5, session.SessionParameterStruct, optional=True
    )
    resumptionID = tlv.OctetStringMember(6, 16, optional=True)
    initiatorResumeMIC = tlv.OctetStringMember(
        7, crypto.AEAD_MIC_LENGTH_BYTES, optional=True
    )


class Sigma2TbsData(tlv.Structure):
    responderNOC = tlv.OctetStringMember(1, crypto.CERTIFICATE_SIZE)
    responderICAC = tlv.OctetStringMember(2, crypto.CERTIFICATE_SIZE, optional=True)
    responderEphPubKey = tlv.OctetStringMember(3, crypto.PUBLIC_KEY_SIZE_BYTES)
    initiatorEphPubKey = tlv.OctetStringMember(4, crypto.PUBLIC_KEY_SIZE_BYTES)


class Sigma2TbeData(tlv.Structure):
    responderNOC = tlv.OctetStringMember(1, crypto.CERTIFICATE_SIZE)
    responderICAC = tlv.OctetStringMember(2, crypto.CERTIFICATE_SIZE, optional=True)
    signature = tlv.OctetStringMember(3, crypto.GROUP_SIZE_BYTES * 2)
    resumptionID = tlv.OctetStringMember(4, 16)


class Sigma2(tlv.Structure):
    responderRandom = tlv.OctetStringMember(1, 32)
    responderSessionId = tlv.IntMember(2, signed=False, octets=2)
    responderEphPubKey = tlv.OctetStringMember(3, crypto.PUBLIC_KEY_SIZE_BYTES)
    encrypted2 = tlv.OctetStringMember(4, Sigma2TbeData.max_length())
    responderSessionParams = tlv.StructMember(
        5, session.SessionParameterStruct, optional=True
    )


class Sigma3TbsData(tlv.Structure):
    initiatorNOC = tlv.OctetStringMember(1, crypto.CERTIFICATE_SIZE)
    initiatorICAC = tlv.OctetStringMember(2, crypto.CERTIFICATE_SIZE, optional=True)
    initiatorEphPubKey = tlv.OctetStringMember(3, crypto.PUBLIC_KEY_SIZE_BYTES)
    responderEphPubKey = tlv.OctetStringMember(4, crypto.PUBLIC_KEY_SIZE_BYTES)


class Sigma3TbeData(tlv.Structure):
    initiatorNOC = tlv.OctetStringMember(1, crypto.CERTIFICATE_SIZE)
    initiatorICAC = tlv.OctetStringMember(2, crypto.CERTIFICATE_SIZE, optional=True)
    signature = tlv.OctetStringMember(3, crypto.GROUP_SIZE_BYTES * 2)


class Sigma3(tlv.Structure):
    encrypted3 = tlv.OctetStringMember(1, Sigma3TbeData.max_length())


class Sigma2Resume(tlv.Structure):
    resumptionID = tlv.OctetStringMember(1, 16)
    sigma2ResumeMIC = tlv.OctetStringMember(2, 16)
    responderSessionID = tlv.IntMember(3, signed=False, octets=2)
    responderSessionParams = tlv.StructMember(
        4, session.SessionParameterStruct, optional=True
    )


def compute_destination_id(
    root_public_key, fabric_id, node_id, initiator_random, identity_protection_key
):
    print("root_public_key", len(root_public_key), "/", root_public_key.hex(":"))
    print("fabric_id", len(fabric_id), "/", fabric_id.hex(":"))
    print("node_id", len(node_id), "/", node_id.hex(":"))
    print("initiator_random", len(initiator_random), "/", initiator_random.hex(":"))
    print(
        "identity_protection_key",
        len(identity_protection_key),
        "/",
        identity_protection_key.hex(":"),
    )
    destination_message = b"".join(
        (initiator_random, root_public_key, fabric_id, node_id)
    )
    return crypto.HMAC(identity_protection_key, destination_message)


if __name__ == "__main__":
    root_public_key = bytes.fromhex(
        "04:4a:9f:42:b1:ca:48:40:d3:72:92:bb:c7:f6:a7:e1:1e:22:20:0c:97:6f:c9:00:db:c9:8a:7a:38:3a:64:1c:b8:25:4a:2e:56:d4:e2:95:a8:47:94:3b:4e:38:97:c4:a7:73:e9:30:27:7b:4d:9f:be:de:8a:05:26:86:bf:ac:fa".replace(
            ":", ""
        )
    )
    fabric_id = bytes.fromhex("62:d3:15:d1:08:c9:06:29".replace(":", ""))
    node_id = bytes.fromhex("14:ef:13:7b:aa:44:55:cd".replace(":", ""))
    initiator_random = bytes.fromhex(
        "7e:17:12:31:56:8d:fa:17:20:6b:3a:cc:f8:fa:ec:2f:4d:21:b5:80:11:31:96:f4:7c:7c:4d:eb:81:0a:73:dc".replace(
            ":", ""
        )
    )
    identity_protection_key = bytes.fromhex(
        " 9b:c6:1c:d9:c6:2a:2d:f6:d6:4d:fc:aa:9d:c4:72:d4".replace(":", "")
    )

    destination_id = compute_destination_id(
        root_public_key, fabric_id, node_id, initiator_random, identity_protection_key
    )
    print(destination_id.hex(":"))
