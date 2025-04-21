host_ip = ''
host_port = 20000


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param )
    fuzzing_READ(session=session)
    fuzzing_Write(session=session)
    fuzzing_Select(session=session)
    fuzzing_Operate(session=session)

    session.fuzz()


def fuzzing_READ(session):
    s_initialize(name="READ")
    with s_block("READ"):
        s_bytes(value=bytes([0x05,0x64]), size=2, max_len=2, name='Start_bytes', fuzzable=True)
        s_bytes(value=bytes([0x0b]), size=1, max_len=1, name='length', fuzzable=True)
        s_bytes(value=bytes([0xc4]), size=1, max_len=1, name='control', fuzzable=True)
        s_bytes(value=bytes([0x03,0x00]), size=2, max_len=2, name='Destination', fuzzable=True)
        s_bytes(value=bytes([0x04,0x00]), size=2, max_len=2, name='source', fuzzable=True)
        s_bytes(value=bytes([0xef, 0x7a]), size=4, max_len=4, name='data_link_header_shecksum', fuzzable=True)
        s_bytes(value=bytes([0xc1]), size=1, max_len=1, name='Transport_control', fuzzable=True)
        s_bytes(value=bytes([0xc1]), size=1, max_len=1, name='APPlication', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Function_code', fuzzable=False)
        s_bytes(value=bytes([0x3c, 0x02, 0x06]), size=3, max_len=3, name='object', fuzzable=True)
        s_bytes(value=bytes([0xb5, 0x76]), size=2, max_len=2, name='Data_chunk_checksum', fuzzable=True)
    session.connect(s_get('READ'))

def fuzzing_Write(session):
    s_initialize(name="Write")
    with s_block("Write"):
        s_bytes(value=bytes([0x05,0x64]), size=2, max_len=2, name='Start_bytes', fuzzable=True)
        s_bytes(value=bytes([0x12]), size=1, max_len=1, name='length', fuzzable=True)
        s_bytes(value=bytes([0xc4]), size=1, max_len=1, name='control', fuzzable=True)
        s_bytes(value=bytes([0x03,0x00]), size=2, max_len=2, name='Destination', fuzzable=True)
        s_bytes(value=bytes([0x04,0x00]), size=2, max_len=2, name='source', fuzzable=True)
        s_bytes(value=bytes([0x15, 0x2d]), size=2, max_len=2, name='data_link_header_shecksum', fuzzable=True)
        s_bytes(value=bytes([0xc1]), size=1, max_len=1, name='Transport_control', fuzzable=True)
        s_bytes(value=bytes([0xc1]), size=1, max_len=1, name='APPlication', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Function_code', fuzzable=False)
        s_bytes(value=bytes([0x32, 0x01, 0x07]), size=3, max_len=3, name='QUalifier', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Quantity', fuzzable=True)
        s_bytes(value=bytes([0xfa, 0x7d, 0x0b, 0x46, 0x0d, 0x01]), size=6, max_len=6, name='Timestamp', fuzzable=True)
        s_bytes(value=bytes([0xc8, 0x63]), size=2, max_len=2, name='Data_chunk_checksum', fuzzable=True)
    session.connect(s_get('Write'))

def fuzzing_Select(session):
    s_initialize(name="Select")
    with s_block("Select"):
        s_bytes(value=bytes([0x05,0x64]), size=2, max_len=2, name='Start_bytes', fuzzable=True)
        s_bytes(value=bytes([0x1a]), size=1, max_len=1, name='length', fuzzable=True)
        s_bytes(value=bytes([0xc4]), size=1, max_len=1, name='control', fuzzable=True)
        s_bytes(value=bytes([0x03,0x00]), size=2, max_len=2, name='Destination', fuzzable=True)
        s_bytes(value=bytes([0x04,0x00]), size=2, max_len=2, name='source', fuzzable=True)
        s_bytes(value=bytes([0xc9, 0xb7]), size=2, max_len=2, name='data_link_header_shecksum', fuzzable=True)
        s_bytes(value=bytes([0xc1]), size=1, max_len=1, name='Transport_control', fuzzable=True)
        s_bytes(value=bytes([0xc1]), size=1, max_len=1, name='APPlication', fuzzable=True)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Function_code', fuzzable=False)
        s_bytes(value=bytes([0x0c, 0x01, 0x28]), size=3, max_len=3, name='QUalifier', fuzzable=True)
        s_bytes(value=bytes([0x01,0x00]), size=2, max_len=2, name='Quantity', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='index', fuzzable=True)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Control_code', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='count', fuzzable=True)
        s_bytes(value=bytes([0x64,0x00,0x00,0x00]), size=4, max_len=4, name='ON_time', fuzzable=True)
        s_bytes(value=bytes([0x7b, 0x5e]), size=2, max_len=2, name='Data_chunk_checksum', fuzzable=True)
        s_bytes(value=bytes([0x64, 0x00, 0x00, 0x00]), size=4, max_len=4, name='off_time', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='control_status', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x5b]), size=2, max_len=2, name='Data_chunk_checksum1', fuzzable=True)
    session.connect(s_get('Select'))

def fuzzing_Operate(session):
    s_initialize(name="Operate")
    with s_block("Operate"):
        s_bytes(value=bytes([0x05,0x64]), size=2, max_len=2, name='Start_bytes', fuzzable=True)
        s_bytes(value=bytes([0x1a]), size=1, max_len=1, name='length', fuzzable=True)
        s_bytes(value=bytes([0xc4]), size=1, max_len=1, name='control', fuzzable=True)
        s_bytes(value=bytes([0x03,0x00]), size=2, max_len=2, name='Destination', fuzzable=True)
        s_bytes(value=bytes([0x04,0x00]), size=2, max_len=2, name='source', fuzzable=True)
        s_bytes(value=bytes([0xc9, 0xb7]), size=2, max_len=2, name='data_link_header_shecksum', fuzzable=True)
        s_bytes(value=bytes([0xc1]), size=1, max_len=1, name='Transport_control', fuzzable=True)
        s_bytes(value=bytes([0xc2]), size=1, max_len=1, name='APPlication', fuzzable=True)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Function_code', fuzzable=False)
        s_bytes(value=bytes([0x0c, 0x01, 0x28]), size=3, max_len=3, name='QUalifier', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='Quantity', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='index', fuzzable=True)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Control_code', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='count', fuzzable=True)
        s_bytes(value=bytes([0x64, 0x00, 0x00, 0x00]), size=4, max_len=4, name='ON_time', fuzzable=True)
        s_bytes(value=bytes([0x83, 0x54]), size=2, max_len=2, name='Data_chunk_checksum', fuzzable=True)
        s_bytes(value=bytes([0x64, 0x00, 0x00, 0x00]), size=4, max_len=4, name='off_time', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='control_status', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x5b]), size=2, max_len=2, name='Data_chunk_checksum1', fuzzable=True)
    session.connect(s_get('Operate'))

if __name__ == "__main__":
    fuzzing_main()