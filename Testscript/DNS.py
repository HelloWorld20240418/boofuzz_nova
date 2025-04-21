from boofuzz import *

host_ip = '192.168.1.200'

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, 53)),
                keep_web_open=False,
                index_start=290000,
                      )

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="DNS")
    with s_block("query"):
        s_bytes(value=bytes([0x00,0x2b]), name='Transaction_ID', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00]), name='flags', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), name='Qustions', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Answer_RRS', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Authority_RRS', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Additional_RRS', fuzzable=False)
        s_string("www.baidu.com", name="Name", fuzzable=True)
        s_bytes(value=bytes([0x00,0x01]), size=2, max_len=2, name='Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Class', fuzzable=False)


        session.connect(s_get('DNS'))
if __name__ == "__main__":
    fuzzing_main()