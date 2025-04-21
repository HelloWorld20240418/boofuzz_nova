host_ip = ''
host_port = 6653

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_OPEN_HELLO(session=session)
    fuzzing_OFPT_FEATURES_REPLY(session=session)
    fuzzing_OFPT_ECHO_REPLY(session=session)
    session.fuzz()
def fuzzing_OPEN_HELLO(session):
    s_initialize(name="OPEN_HELLO")
    with s_block("OPEN_HELLO"):
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='openflow_v4.version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='openflow_v4.type', fuzzable=False)
        s_bytes(value=bytes([0x00,0x08]), size=2, max_len=2, name='openflow_v4.length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x05]), size=4, max_len=4, name='openflow_v4.xid', fuzzable=True)

        session.connect(s_get('OPEN_HELLO'))
def fuzzing_OFPT_FEATURES_REPLY(session):
    s_initialize(name="OFPT_FEATURES_REPLY")
    with s_block("OFPT_FEATURES_REPLY"):
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='openflow_v4.version', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='openflow_v4.type', fuzzable=False)
        s_bytes(value=bytes([0x00,0x20]), size=2, max_len=2, name='openflow_v4.length', fuzzable=False)
        s_bytes(value=bytes([0x10,0xda,0x06,0x5d]), size=4, max_len=4, name='openflow_v4.xid', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x01]), size=8, max_len=8, name='openflow_v4.switch_features.datapath_id', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x01, 0x00]), size=4, max_len=4, name='openflow_v4.switch_features.n_buffers', fuzzable=True)
        s_bytes(value=bytes([0xfe]), size=1, max_len=1, name='openflow_v4.switch_features.n_tables', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='openflow_v4.switch_features.auxiliary_id', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='openflow_v4.switch_features.pad', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x4f]), size=4, max_len=4, name='openflow_v4.switch_features.capabilities', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='openflow_v4.switch_features_reserved', fuzzable=True)

        session.connect(s_get('OFPT_FEATURES_REPLY'))
def fuzzing_OFPT_ECHO_REPLY(session):
    s_initialize(name="OFPT_ECHO_REPLY")
    with s_block("OPEN_HELLO"):
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='openflow_v4.version', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='openflow_v4.type', fuzzable=False)
        s_bytes(value=bytes([0x00,0x08]), size=2, max_len=2, name='openflow_v4.length', fuzzable=False)
        s_bytes(value=bytes([0x01,0xda,0x06,0x5e]), size=4, max_len=4, name='openflow_v4.xid', fuzzable=True)

        session.connect(s_get('OFPT_ECHO_REPLY'))
if __name__ == "__main__":
    fuzzing_main()
