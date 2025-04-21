from boofuzz import *


host_ip = '192.168.16.254'
host_port = 6000

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),
                      keep_web_open=False,
                      )
    fuzzing_define_proto(session=session)
    session.fuzz(max_depth=1)


def fuzzing_define_proto(session):
    s_initialize(name="TCP payload")
    with s_block("TCP"):
        s_string(value="bye", name="TCP segment data")

    session.connect(s_get('TCP payload'))


if __name__ == "__main__":
    fuzzing_main()
