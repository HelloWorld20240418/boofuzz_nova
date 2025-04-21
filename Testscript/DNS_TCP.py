from boofuzz import *


host_ip = '192.168.16.254'
host_port = 53


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),
                      keep_web_open=False,

                      )

    fuzzing_define_proto(session=session)

    session.fuzz(max_depth=1)


def fuzzing_define_proto(session):
    s_initialize(name="DNS")
    s_size("query", output_format="ascii", name="Length", fuzzable=False)

    with s_block("query"):
        s_bytes(value=bytes([0X78, 0X64]), size=2, max_len=2, name='Transaction_ID', fuzzable=False)
        s_bytes(value=bytes([0X01, 0X00]), size=2, max_len=2, name='flags', fuzzable=False)
        s_bytes(value=bytes([0X00, 0X01]), size=2, max_len=2, name='questions', fuzzable=False)
        s_bytes(value=bytes([0X00, 0X00]), size=2, max_len=2, name='Answer_RRS', fuzzable=False)
        s_bytes(value=bytes([0X00, 0X00]), size=2, max_len=2, name='Authority_RRS', fuzzable=False)
        s_bytes(value=bytes([0X00, 0X00]), size=2, max_len=2, name='Additional_RRS', fuzzable=False)
        s_string("www.baidu.com", name="Name", fuzzable=True)
        s_bytes(value=bytes([0x00,0x01]),  name='Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Class', fuzzable=True)


        session.connect(s_get('DNS'))
if __name__ == "__main__":
            fuzzing_main()