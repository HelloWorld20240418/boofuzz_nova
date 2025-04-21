
host_ip = ''
host_port = 143

def fuzzing_main():
    session = Session(target=Target(connection=SocketConnection(host_ip, host_port, proto='tcp')), nova_session_param=nova_session_param)
    s_initialize(name='IMAP FUZZ')
    s_static("A01 ")
    s_group("commands", values=["LIST", "AUTHENTICATE", "LOGIN"])

    with s_block("command", group="commands"):
        s_string("1234", name="imap_command")
        s_static("\r\n")

    session.connect(s_get("IMAP FUZZ"))
    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()