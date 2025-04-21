
host_ip = ''
host_port = 23

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param )

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="TELENT")
    with s_block("TELENT"):
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='will_terminal_type', fuzzable=False)
        s_bytes(value=bytes([0xfb]), size=1, max_len=1, name='command', fuzzable=True)
        s_bytes(value=bytes([0x18]), size=1, max_len=1, name='subcommand', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='will_terminal_speed', fuzzable=False)
        s_bytes(value=bytes([0xfb]), size=1, max_len=1, name='command1', fuzzable=False)
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name='subcommand1', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Wontx_display_location', fuzzable=True)
        s_bytes(value=bytes([0xfc]), size=1, max_len=1, name='command2', fuzzable=True)
        s_bytes(value=bytes([0x23]), size=1, max_len=1, name='subcommand2', fuzzable=True)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Will_new_environment_option', fuzzable=True)
        s_bytes(value=bytes([0xfb]), size=1, max_len=1, name='command3', fuzzable=True)
        s_bytes(value=bytes([0x27]), size=1, max_len=1, name='subcommand3', fuzzable=True)



        s_bytes(value=bytes([0x3d,0x00]), size=2, max_len=2, name='source', fuzzable=True)
        s_bytes(value=bytes([0x80, 0x27]), size=4, max_len=4, name='data_link_header_shecksum', fuzzable=True)

        session.connect(s_get('TELENT'))


if __name__ == "__main__":
    fuzzing_main()