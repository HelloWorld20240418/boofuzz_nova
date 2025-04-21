
host_ip = ''

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, 6001)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="UDP payload")
    with s_block("UDP"):
        s_string(value="bye", name="Data")

    session.connect(s_get('UDP payload'))


if __name__ == "__main__":
    fuzzing_main()
