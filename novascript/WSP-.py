host_ip = ''
host_port = 9200

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_WSP(session=session)

    session.fuzz()

def fuzzing_WSP(session):
    s_initialize(name="Protocol")
    with s_block("Protocol"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='transaction_ID', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='PDU_type', fuzzable=False)
        s_bytes(value=bytes([0x16]), size=1, max_len=1, name='URL_length', fuzzable=False)
        s_bytes(value=bytes([0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77,
        0x61,0x70,0x2e,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x2e,0x63,0x6f,0x6d,0x2f]), size=22, max_len=22, name='URI',fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='header_name', fuzzable=False)
        s_bytes(value=bytes([0x94]), size=1, max_len=1, name='accept_application/vnd.wap.wmlc', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='header_name_1', fuzzable=False)
        s_bytes(value=bytes([0x88]), size=1, max_len=1, name='accept_text/vnd.wap.wml', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='header_name_2', fuzzable=False)
        s_bytes(value=bytes([0xa1]), size=1, max_len=1, name='Accept: image/vnd.wap.wbmp', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='header_name_3', fuzzable=False)
        s_bytes(value=bytes([0x9d]), size=1, max_len=1, name='Accept: image/gif', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='header_name_4', fuzzable=False)
        s_bytes(value=bytes([0x9e]), size=1, max_len=1, name='Accept: image/jpeg', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='header_name_5', fuzzable=False)
        s_bytes(value=bytes([0xa0]), size=1, max_len=1, name='Accept: image/png', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='header_name_6', fuzzable=False)
        s_bytes(value=bytes([0x95]), size=1, max_len=1, name='Accept: application/vnd.wap.wmlscriptc', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='header_name_7', fuzzable=True)
        s_bytes(value=bytes([0x89]), size=1, max_len=1, name='Accept: text/vnd.wap.wmlscript', fuzzable=False)
        s_bytes(value=bytes([0xa9]), size=1, max_len=1, name='Header name: User-Agent (41)', fuzzable=False)
        s_delim("User-Agent: ", name="User-Agent", fuzzable=False)
        s_string("WinWAP/3.2 (3.2.1.28; Win32)", name="User-Agent: ",size=30,max_len=30, fuzzable=False)
        s_delim("Cookie: ", name="space-3", fuzzable=False)
        s_string("PREF=ID=2abac481a479eb86:TM=1125931831:LM=1125931831:S=gI7WUlkrMpCy054v", name="Cookie: ", fuzzable=True)


    session.connect(s_get('Protocol'))


if __name__ == "__main__":
    fuzzing_main()