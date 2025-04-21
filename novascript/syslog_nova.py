host_ip = ''
host_port = 514

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_syslogmessage(session=session)
    session.fuzz()


def fuzzing_syslogmessage(session):
    s_initialize(name="SyslogMessage")


    with s_block("Syslog"):
        s_bytes(value=bytes([0x3c, 0x31, 0x33, 0x3e]), size=4, max_len=4, name='header', fuzzable=False)
        s_bytes(value=bytes([0x31]), size=1,max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0x20]), size=1,max_len=1, name='s0byte', fuzzable=False)
        s_bytes(value=bytes([0x32, 0x30, 0x32,0x34,0x2d,0x31,0x32,0x2d,0x32,0x34,0x54,0x30,0x31,0x3a,0x31,0x34,0x3a,0x33,0x34,0x2e,0x37,0x31,0x31,0x35,0x30,0x34,0x2d,0x30,0x35,0x3a,0x30,0x30]), size=32, max_len=32, name='timestamp', fuzzable=True)
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name='s1byte', fuzzable=False)
        s_bytes(value=bytes([0x6b, 0x61, 0x6c, 0x69]), size=4, max_len=4, name='hostname', fuzzable=False)
        s_bytes(value=bytes([0x20]), size=1,max_len=1, name='s2byte', fuzzable=False)
        s_bytes(value=bytes([0x6b, 0x61, 0x6c, 0x69]), size=4, max_len=4, name='app name', fuzzable=False)
        # s_bytes(value=bytes([0x20]), size=1,max_len=1, name='s1byte', fuzzable=False)
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name='s3byte', fuzzable=False)
        s_bytes(value=bytes([0x2d]), size=1, max_len=2, name='process ID', fuzzable=False)
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name='s4byte', fuzzable=False)

        s_bytes(value=bytes([0x2d]), size=1, max_len=2, name='message ID', fuzzable=False)
        s_bytes(value=bytes([0x20]), size=1,max_len=1, name='s5byte', fuzzable=False)


        s_bytes(value=bytes([0x5b]), size=1, max_len=1, name='syslog.elementheader', fuzzable=False)
        s_bytes(value=bytes([0x74, 0x69, 0x6d, 0x65, 0x51, 0x75, 0x61, 0x6c, 0x69, 0x74, 0x79]), size=11, max_len=11,
                name='syslog.elementname', fuzzable=False)
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name='s6byte', fuzzable=False)
        s_bytes(value=bytes([0x74, 0x7a, 0x4b, 0x6e, 0x6f, 0x77, 0x6e]), size=7, max_len=7, name='syslog.tzKnown_name',
                fuzzable=False)
        s_bytes(value=bytes([0x3d, 0x22]), size=2, max_len=2, name='s7byte', fuzzable=False)
        s_bytes(value=bytes([0x31]), size=3, max_len=3, name='syslog.tzKnown_value', fuzzable=False)
        s_bytes(value=bytes([0x22, 0x20]), size=2, max_len=2, name='s8byte', fuzzable=False)
        s_bytes(value=bytes([0x69, 0x73, 0x53, 0x79, 0x6e, 0x63, 0x65, 0x64]), size=8, max_len=8,
                name='syslog.isSynced_name', fuzzable=True)
        s_bytes(value=bytes([0x3d, 0x22]), size=2, max_len=2, name='s9byte', fuzzable=False)
        s_bytes(value=bytes([0x31]), size=4, max_len=1, name='syslog.isSynced_value', fuzzable=False)
        s_bytes(value=bytes([0x22, 0x20]), size=2, max_len=2, name='s10byte', fuzzable=False)
        s_bytes(value=bytes([0x73, 0x79,0x6e,0x63,0x41,0x63,0x63,0x75,0x72,0x61,0x63, 0x79]), size=12, max_len=12, name='syslog.syncAccuracy_name', fuzzable=True)
        s_bytes(value=bytes([0x3d, 0x22]), size=2, max_len=2, name='s11byte', fuzzable=False)
        s_bytes(value=bytes([0x31, 0x33,0x30,0x30,0x30]), size=5, max_len=5, name='syslog.syncAccuracy_value',
                fuzzable=True)
        s_bytes(value=bytes([0x22, 0x5d, 0x20]), size=3, max_len=3, name='s12byte',fuzzable=False)
        s_bytes(value=bytes([0x54,0x68]), size=20, max_len=20, name='message', fuzzable=True)

    session.connect(s_get("SyslogMessage"))

if __name__ == "__main__":
    fuzzing_main()