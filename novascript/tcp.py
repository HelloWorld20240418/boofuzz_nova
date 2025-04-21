
host_ip = ''
host_port = 6000

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="TCP payload")
    with s_block("TCP"):
        s_string(value="bye", name="TCP segment data")

    session.connect(s_get('TCP payload'))


if __name__ == "__main__":
    fuzzing_main()
