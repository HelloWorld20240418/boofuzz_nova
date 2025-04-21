host_ip = ''
host_port = 319

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_PTPV2(session=session)

    session.fuzz()


def fuzzing_PTPV2(session):
    s_initialize(name="PTPV2")
    with s_block("PTPV2"):
        s_bytes(value=bytes([0x12]), size=1, max_len=1, name='ptp.v2.majorsdoid', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='ptp.v2.minorversionptp', fuzzable=False)
        s_bytes(value=bytes([0x00,0x36]), size=2, max_len=2, name='ptp.v2.messagelength', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='ptp.v2.domainnumber', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='ptp.v2.minorsdoid', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='ptp.v2.flags', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=8, max_len=8, name='text', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='ptp.v2.messagetypespecific', fuzzable=False)
        s_bytes(value=bytes([0x00,0x80,0x63,0xff,0xff,0x00,0x09,0xba]), size=8, max_len=8, name='ptp.v2.clockidentity', fuzzable=True)
        s_bytes(value=bytes([0x00,0x01]), size=2, max_len=2, name='ptp.v2.sourceportid', fuzzable=False)
        s_bytes(value=bytes([0x9e,0x48]), size=2, max_len=2, name='ptp.v2.sequenceid', fuzzable=False)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='ptp.v2.controlfield', fuzzable=False)
        s_bytes(value=bytes([0x0f]), size=1, max_len=1, name='ptp.v2.logmessageperiod', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x45,0xb1,0x11,0x51]), size=6, max_len=6, name='ptp.v2.pdrq.origintimestamp.seconds', fuzzable=True)
        s_bytes(value=bytes([0x04,0x72,0xf9,0xc1]), size=4, max_len=4, name='ptp.v2.pdrq.origintimestamp.nanoseconds', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=10, max_len=10, name='end', fuzzable=True)

    session.connect(s_get('PTPV2'))

if __name__ == "__main__":
    fuzzing_main()