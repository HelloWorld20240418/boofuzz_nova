
host_ip = ''
host_port = 21

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_user(session=session)
    fuzzing_pass(session=session)
    fuzzing_stor(session=session)
    fuzzing_retr(session=session)
    session.fuzz()


def fuzzing_user(session):
    s_initialize("user")
    s_string("USER")
    s_delim(" ")
    s_string("anonymous")
    s_static("\r\n")
    session.connect(s_get("user"))

def fuzzing_pass(session):
    s_initialize("pass")
    s_string("PASS")
    s_delim(" ")
    s_string("james")
    s_static("\r\n")
    session.connect(s_get("user"), s_get("pass"))

def fuzzing_stor(session):
    s_initialize("stor")
    s_string("STOR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")
    session.connect(s_get("pass"), s_get("stor"))

def fuzzing_retr(session):
    s_initialize("retr")
    s_string("RETR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")
    session.connect(s_get("pass"), s_get("retr"))

if __name__ == "__main__":
    fuzzing_main()
