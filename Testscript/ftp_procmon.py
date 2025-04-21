
from boofuzz import *


def main():
    
    target_ip = "192.168.1.200"
    start_cmd = ["python", "C:\\ftpd\\ftpd.py"]

    procmon = ProcessMonitor(target_ip, 26002)
    procmon.set_options(start_commands=[start_cmd])

    session = Session(
        target=Target(
            connection=TCPSocketConnection(target_ip, 21),
            monitors=[procmon],
        ),
        sleep_time=1,
    )
    # fmt: on

    s_initialize("user")
    s_string("USER")
    s_delim(" ")
    s_string("anonymous")
    s_static("\r\n")

    s_initialize("pass")
    s_string("PASS")
    s_delim(" ")
    s_string("james")
    s_static("\r\n")

    s_initialize("stor")
    s_string("STOR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    s_initialize("retr")
    s_string("RETR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.connect(s_get("pass"), s_get("stor"))
    session.connect(s_get("pass"), s_get("retr"))

    session.fuzz()


if __name__ == "__main__":
    main()
