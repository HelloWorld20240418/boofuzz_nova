
host_ip = ''
host_port = 22

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="SSHv2 Version Exchange")
    s_static("SSH-")                     # 协议标识
    s_static("2", name="major_version")  # 主版本号
    s_delim(".")                         # 分隔符
    s_string("0", name="minor_version")  # 次版本号
    s_delim("-")                         # 分隔符
    s_string("OpenSSH_7.9", name="software_version")  # 软件版本
    s_static("\r\n") 

    session.connect(s_get('SSHv2 Version Exchange'))


if __name__ == "__main__":
    fuzzing_main()
