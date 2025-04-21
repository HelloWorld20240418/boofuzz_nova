
interface_port=''
target_mac_str = 'd4:f5:27:1b:93:df'
target_mac = target_mac_str.split(':')
source_mac_str = 'b4:05:5d:15:3c:78'
source_mac = source_mac_str.split(':')

def fuzzing_main():
    session = Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="LLC_S7COMM")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination',
            fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source',
            fuzzable=False)
        s_bytes(value=bytes([0x00, 0xda]), size=2, max_len=2, name='Length', fuzzable=False)
    with s_block("Logical-Link Control"):
        s_bytes(value=bytes([0xfe]), size=1, max_len=1, name='DSAP', fuzzable=False)
        s_bytes(value=bytes([0xfe]), size=1, max_len=1, name='SSAP', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Control field', fuzzable=False)
    with s_block("CLNP"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Inactive subset', fuzzable=False)
    with s_block("COTP"):
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name='length', fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name='PDU Type', fuzzable=False)
        s_bytes(value=bytes([0x03, 0x00]), size=2, max_len=2, name='Destination reference', fuzzable=False)
        s_bytes(value=bytes([0x80, 0x00, 0x84, 0xe4]), size=4, max_len=4, name='TPDU number', fuzzable=False)
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name='Protocol Id', fuzzable=False)
            s_bytes(value=bytes([0x07]), size=1, max_len=1, name='ROSCTR', fuzzable=False)
            s_bytes(value=bytes([0x54, 0xec]), size=2, max_len=2, name='Redundancy Identification', fuzzable=False)
            s_bytes(value=bytes([0x30, 0x05]), size=2, max_len=2, name='Protocol Data Unit Reference', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x0c]), size=2, max_len=2, name='Parameter length', fuzzable=False)
            s_bytes(value=bytes([0x00, 0xb8]), size=2, max_len=2, name='Data length', fuzzable=False)
        with s_block("Parameter"):
            s_bytes(value=bytes([0x00, 0x01, 0x12]), size=3, max_len=3, name='Parameter head', fuzzable=True)
            s_bytes(value=bytes([0x08]), size=1, max_len=1, name='Parameter length', fuzzable=False)
            s_bytes(value=bytes([0x12]), size=1, max_len=1, name='Method', fuzzable=False)
            s_bytes(value=bytes([0x46]), size=1, max_len=1, name='Type', fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Subfunction', fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='sequence number', fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Data unit reference number', fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Last data unit', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=1, max_len=1, name='Error code', fuzzable=False)
        with s_block("Data"):
            s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Return code', fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name='Transport size', fuzzable=False)
            s_bytes(value=bytes([0x00, 0xb4]), size=2, max_len=2, name='Length', fuzzable=True)
            s_bytes(value=bytes([0x12]), size=1, max_len=1, name='Variable specification', fuzzable=False)
            s_bytes(value=bytes([0x06]), size=1, max_len=1, name='Length of folowing address specification', fuzzable=False)
            s_bytes(value=bytes([0x13]), size=1, max_len=1, name='Syntax Id', fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='PBC BSEND/BRECV unknown', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x01]), size=4, max_len=4, name='PBC BSEND/BRECV R_ID', fuzzable=False)
            s_bytes(value=bytes([0x00, 0xaa]), size=2, max_len=2, name='PBC BSEND/BRECV LEN', fuzzable=False)
            s_string(value='S7COMM', size=170, max_len=170, name='Data')

    session.connect(s_get('LLC_S7COMM'))


if __name__ == "__main__":
    fuzzing_main()
