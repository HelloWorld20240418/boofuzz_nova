from boofuzz import *
interface_port = ''
src_ip = []
dst_ip = []
interface_port=''
target_mac_str = 'd4:f5:27:1b:93:df'
target_mac = target_mac_str.split(':')
source_mac_str = 'b4:05:5d:15:3c:78'
source_mac = source_mac_str.split(':')

def fuzzing_main():
    session = Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)), nova_session_param=nova_session_param )
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="ANSI_MAP")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination',
            fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source',
            fuzzable=False)
        s_bytes(value=bytes([0x08, 0x00]), size=2, max_len=2, name='Type', fuzzable=False)
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x90]), size=2, max_len=2, name='Total_length', fuzzable=False)
        s_bytes(value=bytes([0x7a,0x93]), size=2, max_len=2, name='identification', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='time_to_live', fuzzable=False)
        s_bytes(value=bytes([0x84]), size=1, max_len=1, name='protocol', fuzzable=False)
        s_checksum("IPv4", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes(src_ip), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=4, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("SCTP"):
        s_bytes(value=bytes([0x0b,0x58]), size=1, max_len=1, name='src_port', fuzzable=True)
        s_bytes(value=bytes([0x0b,0x58]), size=1, max_len=1, name='dst_port', fuzzable=False)
        s_bytes(value=bytes([0xd0, 0xa0,0x9b,0x92]), size=4, max_len=4, name='Verification_tag', fuzzable=False)
        s_bytes(value=bytes([0xd0, 0xa0,0x9b,0x92]), size=4, max_len=4, name='checksumsctp', fuzzable=False)
        #s_checksum("SCTP", algorithm='ipv4', name='Checksum', endian='>', length=4, fuzzable=False)
        s_bytes(value=bytes([0x00, 0x03,0x00,0x70,0x00,0x00,0x0f,0x42,0x00,0x05,0x00,0x37,0x00,0x00,0x00,0x02]), size=16, max_len=16, name='data_chunk', fuzzable=True)
    with s_block("m2ua"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='rsd', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='message_class', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='message_type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x06]), size=4, max_len=4, name='message_length', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='parameter_tag', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='parameter_length2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x3e]), size=4, max_len=4, name='interface_identifier', fuzzable=False)
        s_bytes(value=bytes([0x03, 0x00,0x00,0x4e]), size=4, max_len=4, name='data1', fuzzable=False)
    with s_block("MTPL3"):
        s_bytes(value=bytes([0x83]), size=1, max_len=1, name='messae_service_information_octet', fuzzable=False)
        s_bytes(value=bytes([0x0a, 0x80,0x04,0x00]), size=4, max_len=4, name='routing_label', fuzzable=False)
    with s_block("SCCP"):
        s_bytes(value=bytes([0x09]), size=1, max_len=1, name='message_type', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='protocol', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='sccp.variable_pointer1', fuzzable=False)
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name='sccp.variable_pointer2', fuzzable=False)
        s_bytes(value=bytes([0x0b]), size=1, max_len=1, name='sccp.variable_pointer3', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='header1', fuzzable=False)
        s_bytes(value=bytes([0x43, 0x0a, 0x00, 0x08]), size=4, max_len=4, name='text', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='header12', fuzzable=False)
        s_bytes(value=bytes([0x43, 0x12, 0x00, 0x0c]), size=4, max_len=4, name='text2', fuzzable=False)
    with s_block("ANSI_TCAP"):
        s_bytes(value=bytes([0x35]), size=1, max_len=1, name='header3', fuzzable=False)
        s_bytes(value=bytes([0xe2, 0x33,0xc7,0x04]), size=4, max_len=4, name='HEADER', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x00]), size=4, max_len=4, name='ansi_tcap.identifier', fuzzable=True)
        s_bytes(value=bytes([0xe8, 0x2b,0xe9,0x29]), size=4, max_len=4, name='parameter_length3', fuzzable=False)
        s_bytes(value=bytes([0xcf, 0x01, 0x00, 0xd1, 0x02, 0x09, 0x35, 0xf2, 0x20, 0x9f, 0x69, 0x00, 0x9f, 0x74, 0x00, 0x9f, 0x81, 0x00, 0x01, 0x08, 0x88, 0x05, 0x16, 0x19, 0x32, 0x04, 0x00, 0x9f, 0x81, 0x41, 0x01, 0x01, 0x9f, 0x81, 0x43, 0x05, 0x22, 0x22, 0x22, 0x22, 0x22]), size=41, max_len=41, name='parameter_length', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='pading', fuzzable=False)

    session.connect(s_get('ANSI_MAP'))


if __name__ == "__main__":
    fuzzing_main()
