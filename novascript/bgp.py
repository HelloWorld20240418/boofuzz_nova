host_ip = ''
host_port = 179

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_BGP_OPEN_Message(session=session)
    fuzzing_BGP_OPEN_Message_Optional_Parameters(session=session)
    fuzzing_BGP_KEEPALIVE_Message(session=session)
    fuzzing_BGP_UPDATE_Message(session=session)
    fuzzing_BGP_NOTIFICATION_Message(session=session)
    fuzzing_BGP_NOTIFICATION_Message_Shutdown_Communication(session=session)
    session.fuzz()



    # ---------- BGP OPEN Message ---------- #
def fuzzing_BGP_OPEN_Message(session):
    s_initialize(name="BGP_OPEN_Message")
    with s_block("BGP"):
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff]), size=16, max_len=16, name="marker", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x1d]), size=2, max_len=2, name="length", fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name="type", fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name="version", fuzzable=False)
        s_bytes(value=bytes([0xfe, 0x09]), size=2, max_len=2, name="my as", fuzzable=False)
        s_bytes(value=bytes([0x00, 0xb4]), size=2, max_len=2, name="hold time", fuzzable=False)
        s_bytes(value=bytes([0xc0, 0xa8, 0x00, 0x0f]), size=4, max_len=4, name="BGP Identifier")
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="optional parameters length", fuzzable=False)
    session.connect(s_get('BGP_OPEN_Message'))

    # ---------- BGP OPEN Message Optional Parameters---------- #
def fuzzing_BGP_OPEN_Message_Optional_Parameters(session):
    s_initialize(name="BGP_OPEN_Message_Optional_Parameters")
    with s_block("BGP"):
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff]), size=16, max_len=16, name="marker", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x3d]), size=2, max_len=2, name="length", fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name="type", fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name="version", fuzzable=False)
        s_bytes(value=bytes([0x5b, 0xa0]), size=2, max_len=2, name="my as", fuzzable=False)
        s_bytes(value=bytes([0x00, 0xb4]), size=2, max_len=2, name="hold time", fuzzable=False)
        s_bytes(value=bytes([0xac, 0x12, 0x00, 0x03]), size=4, max_len=4, name="BGP Identifier")
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name="optional parameters length", fuzzable=False)
        with s_block("Optional Parameter"):
            s_bytes(value=bytes([0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01]), size=8, max_len=8,
                    name="Optional Parameter 1")
            s_bytes(value=bytes([0x02, 0x02, 0x80, 0x00]), size=4, max_len=4, name="Optional Parameter 2")
            s_bytes(value=bytes([0x02, 0x02, 0x02, 0x00]), size=4, max_len=4, name="Optional Parameter 3")
            s_bytes(value=bytes([0x02, 0x06, 0x41, 0x04, 0x00, 0x01, 0x00, 0x00]), size=8, max_len=8,
                    name="Optional Parameter 4")
            s_bytes(value=bytes([0x02, 0x06, 0x45, 0x04, 0x00, 0x01, 0x01, 0x01]), size=8, max_len=8,
                    name="Optional Parameter 5")
    session.connect(s_get('BGP_OPEN_Message_Optional_Parameters'))


    # ---------- BGP KEEPALIVE Message ---------- #
def fuzzing_BGP_KEEPALIVE_Message(session):
    s_initialize(name="BGP_KEEPALIVE_Message")
    with s_block("BGP"):
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff]), size=16, max_len=16, name="marker", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x13]), size=2, max_len=2, name="length", fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name="type", fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1)
    session.connect(s_get('BGP_KEEPALIVE_Message'))

    # ---------- BGP UPDATE Message ---------- #
def fuzzing_BGP_UPDATE_Message(session):
    s_initialize(name="BGP_UPDATE_Message")
    with s_block("BGP"):
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff]), size=16, max_len=16, name="marker", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x40]), size=2, max_len=2, name="length", fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="type", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Withdrawn Routes Length", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x27]), size=2, max_len=2, name="Total Path Attribute Length", fuzzable=False)
        with s_block("Path attributes"):
            s_bytes(value=bytes([0x40, 0x01, 0x01, 0x01]), size=4, max_len=4, name="path attribute 1")
            s_bytes(value=bytes([0x40, 0x02, 0x00]), size=3, max_len=3, name="path attribute 2")
            s_bytes(value=bytes([0x40, 0x03, 0x04, 0xc0, 0xa8, 0x00, 0x21]), size=7, max_len=7, name="path attribute 3")
            s_bytes(value=bytes([0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00]), size=7, max_len=7, name="path attribute 4")
            s_bytes(value=bytes([0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64]), size=7, max_len=7, name="path attribute 5")
            s_bytes(value=bytes([0xc0, 0x08, 0x08, 0xfe, 0x09, 0x01, 0xf4, 0xfe, 0x09, 0x02, 0x58]), size=11,
                    max_len=11,
                    name="path attribute 6")
        s_bytes(value=bytes([0x08, 0x0a]), size=2, max_len=2, name="Network Layer Reachability Information",
                fuzzable=False)
    session.connect(s_get('BGP_UPDATE_Message'))
    # ---------- BGP NOTIFICATION Message ---------- #
def fuzzing_BGP_NOTIFICATION_Message(session):
    s_initialize(name="BGP_NOTIFICATION_Message")
    with s_block("BGP"):
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff]), size=16, max_len=16, name="marker", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x15]), size=2, max_len=2, name="length", fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="type", fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name="Major error Code")
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name="Minor error Code")
    session.connect(s_get('BGP_NOTIFICATION_Message'))

    # ---------- BGP NOTIFICATION Message Shutdown Communication ---------- #
def fuzzing_BGP_NOTIFICATION_Message_Shutdown_Communication(session):
    s_initialize(name="BGP_NOTIFICATION_Message_Shutdown_Communication")
    with s_block("BGP"):
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff]), size=16, max_len=16, name="marker", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x92]), size=2, max_len=2, name="length", fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="type", fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name="Major error Code", fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="Minor error Code", fuzzable=False)
        s_bytes(value=bytes([0x7c]), size=1, max_len=1, name="BGP Shutdown Communication Length", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00]), size=124, max_len=124, name="Shutdown Communication")
    session.connect(s_get('BGP_NOTIFICATION_Message_Shutdown_Communication'))


if __name__ == "__main__":
    fuzzing_main()
