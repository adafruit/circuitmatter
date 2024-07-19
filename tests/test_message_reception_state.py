from circuitmatter import MessageReceptionState


def test_basics():
    """These test the common window behavior"""
    state = MessageReceptionState(123)
    assert state.message_counter == 123

    # Older messages are not ok
    assert state.process_counter(122)

    # The current max is not ok
    assert state.process_counter(123)

    # A new value is ok
    assert not state.process_counter(126)

    #
    assert state.process_counter(123)

    assert not state.process_counter(124)

    assert not state.process_counter(125)

    assert state.process_counter(124)


def test_window_wrapping():
    """Test wrapping the window data across a rollover"""
    state = MessageReceptionState(123, rollover=True)
    assert state.message_counter == 123

    # Move to the end of the range
    assert not state.process_counter(0xFFFFFFFF)

    # Older is ok when in the window.
    assert not state.process_counter(0xFFFFFFF0)

    # A new value is ok. Window is now 0xFFFFFFF0 to 15
    assert not state.process_counter(16)

    assert state.process_counter(0xFFFFFFF0)

    assert state.process_counter(0xFFFFFFFF)

    assert not state.process_counter(1)

    assert not state.process_counter(0xFFFFFFF8)


def test_unencrypted():
    """These test the common window behavior"""
    state = MessageReceptionState(123, rollover=True, encrypted=False)
    assert state.message_counter == 123

    # Older messages are not ok
    assert state.process_counter(123 - 32)

    # Older messages outside the window are ok
    assert not state.process_counter(123 - 32 - 1)

    assert not state.process_counter(124)


def test_encrypted_no_rollover():
    """These test the common window behavior"""
    state = MessageReceptionState(123, rollover=False, encrypted=True)
    assert state.message_counter == 123

    # Older messages are not ok
    assert state.process_counter(123 - 32)

    # Older messages outside the window are not ok
    assert state.process_counter(123 - 32 - 1)

    # Older messages outside the window are not ok
    assert state.process_counter(0)

    # All newer numbers are ok
    assert not state.process_counter(0xFFFFFFFE)

    # Ok because it is in the window
    assert not state.process_counter(0xFFFFFFFD)

    # All older messages outside the window are not ok
    assert state.process_counter(0)


def test_encrypted_with_rollover():
    """These test the common window behavior"""
    state = MessageReceptionState(123, rollover=True, encrypted=True)
    assert state.message_counter == 123

    # Older messages are not ok
    assert state.process_counter(123 - 32)

    # Older messages outside the window are not ok
    assert state.process_counter(123 - 32 - 1)

    # Older messages outside the window are not ok
    assert state.process_counter(0)

    # Numbers wrapped back within the 2**31 window are not ok
    assert state.process_counter(0xFFFFFFFE)

    assert not state.process_counter(0x80000000)

    assert not state.process_counter(0xFFFFFFFE)

    # Ok because it is in the window
    assert not state.process_counter(0xFFFFFFFD)

    # All older messages outside the window are not ok
    assert state.process_counter(0xFFFFFFFE - 32 - 32)

    assert state.process_counter(0xFFFFFFFE - 0x80000000)

    # It is ok to wrap back around outside the 2**31 window.
    assert not state.process_counter(0xFFFFFFFE - 0x80000000 - 1)
