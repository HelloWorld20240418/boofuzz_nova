
host_ip = ''
host_port = 5901

def fuzzing_main():
    session = Session(target=Target(connection=SocketConnection(host_ip, host_port, proto='tcp')), nova_session_param=nova_session_param)

    s_initialize(name="Handshake")
    with s_block("ProtocolVersion"):
        s_string("RFB", name='RFB')
        s_delim(" ", name='space-1')
        s_string("003", name='Version1')
        s_delim(".", name='space-2')
        s_string('008', name='Version2')
        s_delim("\n", name="end")

    session.connect(s_get("Handshake"))

    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()
