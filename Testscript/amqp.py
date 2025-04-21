
from boofuzz import *


host_ip = '192.168.16.254'
host_port = 5672

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)))
    fuzzing_AMQP(session=session)
    session.fuzz()


def fuzzing_AMQP(session):
    s_initialize(name="OPEN")
    with s_block("Advanced Message Queuing Protocol"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='tpye', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Channel', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x05]), size=4, max_len=4, name='Length', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x14]), size=2, max_len=2, name='Class', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name='Method', fuzzable=False)
        s_bytes(value=bytes([0x00, 0xce]), name='end', fuzzable=True)



    session.connect(s_get('OPEN'))
if __name__ == "__main__":
    fuzzing_main()