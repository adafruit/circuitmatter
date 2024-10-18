from circuitmatter import certificates, pase


def test_basic():
    vendor_id = 0xFFF4
    product_id = 0x1234
    discriminator = 2721
    passcode = 42430398
    assert (
        pase.compute_qr_code(vendor_id, product_id, discriminator, passcode)
        == "MNOA5D4V0163Z072Y00"
    )
    assert certificates.compute_manual_code(discriminator, passcode) == "2449-902-5895"


def test_min():
    vendor_id = 0xFFF4
    product_id = 0x1234
    discriminator = 0
    passcode = 1
    assert (
        pase.compute_qr_code(vendor_id, product_id, discriminator, passcode)
        == "MNOA55UM00ID0000000"
    )
    assert certificates.compute_manual_code(discriminator, passcode) == "0000-010-0007"


def test_max():
    vendor_id = 0xFFF4
    product_id = 0x1234
    discriminator = 0xFFF
    passcode = 99999998
    assert (
        pase.compute_qr_code(vendor_id, product_id, discriminator, passcode)
        == "MNOA5N15271DQ36B420"
    )
    assert certificates.compute_manual_code(discriminator, passcode) == "3575-986-1036"
