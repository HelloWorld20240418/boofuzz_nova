

host_ip = ''
host_port = 6667


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_IRC_ISON(session=session)
    fuzzing_IRC_WHO(session=session)
    session.fuzz()


def fuzzing_IRC_ISON(session):
    s_initialize(name="IRC_ISON")
    with s_block("IRC_ISON"):
         s_bytes(value=bytes([0x49,0x53,0x4f,0x4e]), size=4, max_len=4, name="command", fuzzable=False)
         s_bytes(value=bytes([0x54,0x68,0x75,0x6e,0x66,0x69,0x73,0x63,0x68 ]), size=9, max_len=9, name="parameter", fuzzable=False)
         s_bytes(value=bytes([0x53,0x6d,0x69,0x6c,0x65,0x79]), size=6, max_len=6, name="parameter1", fuzzable=False)
         s_bytes(value=bytes([0x20]), size=1, max_len=1, name='parameter.header', fuzzable=False)
         s_bytes(value=bytes([0x53, 0x6d, 0x69, 0x6c, 0x65, 0x79,0x47]), size=6, max_len=6, name="parameter2", fuzzable=True)
         s_bytes(value=bytes([0x0a]), size=1, max_len=1, name='parameter.end', fuzzable=False)

def fuzzing_IRC_WHO(session):
    s_initialize(name="IRC_WHO")
    with s_block("IRC_WHO"):
        s_bytes(value=bytes([0x57, 0x48, 0x4f,0X20]), size=4, max_len=4, name="command", fuzzable=True)
        s_bytes(value=bytes([0x23, 0x72, 0x6F, 0x6B, 0x79, 0x6d, 0x6f, 0x74, 0x69,0x6f,0x6e]), size=11, max_len=11,name="parameter", fuzzable=True)
        s_bytes(value=bytes([0x0a]), size=1, max_len=1, name='parameter.end', fuzzable=True)

    session.connect(s_get('IRC_ISON'))
    session.connect(s_get('IRC_WHO'))



if __name__ == "__main__":
    fuzzing_main()
