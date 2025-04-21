
host_ip = ''
host_port = 22

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    Version_Exchange(session=session)
    session.fuzz()


def Version_Exchange(session):
    s_initialize(name="Protocol Version Exchange")
    with s_block("Protocol"):
        s_string("SSH-1.5-OpenSSH_5.3", name='Protocol', fuzzable=False)
        s_static("\r\n", name="Host-Line-CRLF")

    s_initialize(name="SESSION_KEY")
    with s_block("SSH Version "):
        s_bytes(value=bytes([0x00, 0x00, 0x01, 0x14]), name='ssh.packet_length', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), name='ssh.padding_length', fuzzable=False)
        s_bytes(value=bytes([0x03]), name='ssh.message_code', fuzzable=False)
        s_string(
            "0331ac17bfb1dfe829080082f704195b8dd923931dbe291c970f45bb0fa7affb9109fa377f31b96c238267d413e757ee53884e93cf4d9220bfc07a34f3fcf138b9865ec94b2abc159c75949f0148acab5e4d960bf871a70a0ae1e44cb963727dde6538a24876efafe932bd67f335766600d5a95dfbc0b4b4b73495fa915cf3e5f4e2f33accd9c17cd4689344002b46e68b91223ee5b3c21db871e15a279d45f5684b045430d4291672ca1af1184c81887519f3864c23b4c850b19bacd511466a42b6fef8abbeca80ef639aacbaa94b693ebcabd7c275aa566c63664a03299b68ac495f208f667959525aa31a80e2b7e891cdbff8eac04119ac1b8d5f096758000c904497b8ab40113fc477000000033f00eaf1",
            name='ssh.payload', fuzzable=True)

 
    s_initialize(name="ENCRYPED_PACKET")
    with s_block("SSH Version "):
       s_bytes(value=bytes([0x00, 0x00, 0x00, 0x0d]), name='ssh.packet_length', fuzzable=False)
       s_bytes(value=bytes([0x42, 0x3d, 0x4e]), name='ssh.padding_length', fuzzable=False)
       s_bytes(value=bytes([0x91, 0x65, 0x0e, 0x64, 0x36, 0x5c, 0xb6, 0x84, 0xa0, 0xcd, 0x91, 0xed, 0x38]),
                 name='palyload', fuzzable=True)

    session.connect(s_get('Protocol Version Exchange'))
    session.connect(s_get('Protocol Version Exchange'), s_get('SESSION_KEY'))
    session.connect(s_get('SESSION_KEY'), s_get('ENCRYPED_PACKET'))
if __name__ == "__main__":
    fuzzing_main()
