import socket

from boofuzz import *


host_ip = '192.168.16.254'
host_port = 3306



def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),
                      keep_web_open=False,
                      # index_start=239000,
                      # index_end=239512,
                      )
    fuzzing_mysql(session=session)

    session.fuzz()

def fuzzing_mysql(session):
    s_initialize(name="Mysql")
    s_size(block_name="Login Request", length=3, name="Packet Length", fuzzable=False)
    s_byte(value=0x01, name="Packet Number", fuzzable=False)
    with s_block("Login Request"):
            s_bytes(value=bytes([0x85,0xa6]), name="Client Capabilities", fuzzable=False)
            s_bytes(value=bytes([0x0f,0x20]), name="Extended Client Capabilities", fuzzable=False)
            s_bytes(value=bytes([0x00,0x00,0x00,0x01]), name="MAX Packet", fuzzable=False)
            s_byte(value=0x21, name="Charset", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), name="Unused", fuzzable=False)
            s_string("admin", name="Username", fuzzable=True)
            s_byte(value=0x00, name="null",fuzzable=False)
            s_byte(value=0x14, name="null1",fuzzable=False)
            s_bytes(value=bytes(
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00]), name="Password", size=20,fuzzable=True)
            s_static("mysql_native_password", name="Client Auth Plugin")
            s_byte(value=0x00, name="null2",fuzzable=False)



    session.connect(s_get("Mysql"))

if __name__ == "__main__":
    fuzzing_main()