
host_ip = ''
host_port = 5060

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_SIP_Invite(session=session)
    session.fuzz()


def fuzzing_SIP_Invite(session):
    s_initialize(name="SIP INVITE")
    with s_block("SIP_Requestline"):
        #s_group("sipmethod",["INVITE", "ACK", "OPTIONS", "BYE", "CANCEL", "REGISTER"])
        s_static("INVITE")
        s_delim(" ", name="space-1", fuzzable=False)
        s_static("sip:")
        #s_string("1@domain.com", max_len=50, fuzzable=True)
        s_string("user", max_len=10,name='userpart_invite1', fuzzable=True)
        s_static("@")
        s_string("domain.com", max_len=15,name='hostpart_invite1', fuzzable=True)
        s_delim(" ", name="space-2", fuzzable=False)
        s_static("SIP/2.0")
        s_bytes(value=bytes([0x0d, 0x0a]), size=2, max_len=2, name='newline1', fuzzable=False)
    with s_block("Message_Header"):
        s_static("Via: SIP/2.0/UDP ")
        s_string("host.domain.com", max_len=15, name='sentbyaddress', fuzzable=True)
        s_static(";branch=")
        s_bytes(value=bytes([0x7a, 0x39, 0x68, 0x47, 0x34, 0x62, 0x4b, 0x37, 0x37, 0x36, 0x61, 0x73]), size=12,max_len=64,name='branch', fuzzable=True)
        s_bytes(value=bytes([0x0d, 0x0a]), size=2, max_len=2, name='newline2', fuzzable=False)
        s_static("Max-Forwards: ")
        s_bytes(value=bytes([0x37, 0x30]), size=2, max_len=3, name='max_forwords', fuzzable=False)
        s_bytes(value=bytes([0x0d, 0x0a]), size=2, max_len=2, name='newline3', fuzzable=False)
        s_static("To: sip:")
        s_string("user", max_len=10, name='userpart_invite2', fuzzable=True)
        s_static("@")
        s_string("domain.com", max_len=15, name='hostpart_invite2', fuzzable=True)
        s_bytes(value=bytes([0x0d, 0x0a]), size=2, max_len=2, name='newline4', fuzzable=False)
        s_static("From: sip:")
        s_string("caller", max_len=10, name='callerpart_invite2', fuzzable=True)
        s_static("@")
        s_string("domain.com", max_len=15, name='callerhostpart_invite2', fuzzable=True)
        s_static(";tag=")
        s_string("1928301774", max_len=20, name="tag_value", fuzzable=True)
        s_bytes(value=bytes([0x0d, 0x0a]), size=2, max_len=2, name='newline5',fuzzable=False)
        s_static("Call-ID: ")
        s_string("a84b4c76e66710", size=14, max_len=14, name='call_id', fuzzable=True)
        s_bytes(value=bytes([0x0d, 0x0a]), size=2, max_len=2, name='newline6',fuzzable=False)
        s_static("CSeq: ")
        s_string("314159 ", max_len=10, name="cseq_number", fuzzable=False)
        #s_delim(" ", name="space-3", fuzzable=False)
        #s_group("sipmethod", ["INVITE", "ACK", "OPTIONS", "BYE", "CANCEL", "REGISTER"])
        s_static("INVITE")
        s_bytes(value=bytes([0x0d, 0x0a]), size=2, max_len=2, name='newline7', fuzzable=False)
        s_static("Contact: <sip:")
        #s_string("1@domain.com", max_len=50, fuzzable=True)
        s_string("caller", max_len=10, name='uriuserpart', fuzzable=True)
        s_static("@")
        s_string("host.domain.com", max_len=15, name='urihostpart', fuzzable=True)
        s_static(">")
        s_bytes(value=bytes([0x0d, 0x0a]), size=2, max_len=2, name='newline8', fuzzable=False)
        s_static("Content-Type: application/sdp")
        s_bytes(value=bytes([0x0d, 0x0a]), size=2, max_len=2, name='newline9', fuzzable=False)
        #s_static("Content-Length: ")
        #s_string("142", max_len=10, name="content_length",fuzzable=False)
        s_bytes(value=bytes([0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x31, 0x34, 0x32, 0x0d, 0x0a]), size=21, max_len=21, name='content_length', fuzzable=False)
        s_bytes(value=bytes([0x0d, 0x0a]), size=2, max_len=2, name='newline10', fuzzable=False)
    with s_block("SIP_Body"):
        s_bytes(value=bytes([0x3c, 0xe6, 0xb6, 0x88, 0xe6, 0x81, 0xaf, 0xe6, 0xbd, 0x93, 0x31]), size=11, max_len=50, name='body', fuzzable=True)

    session.connect(s_get("SIP INVITE"))

if __name__ == "__main__":
    fuzzing_main()
