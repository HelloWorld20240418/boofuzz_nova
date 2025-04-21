
from boofuzz import *

host_ip = '192.168.16.254'
host_port = 21

def main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)))

    define_proto(session=session)
    session.fuzz()


def define_proto(session):
    user = Request("user", children=(
        String(name="key", default_value="USER", fuzzable=False),
        Delim(name="space", default_value=" ", fuzzable=True),
        String(name="val", default_value="anonymous", fuzzable=True),
        Static(name="end", default_value="\r\n"),
    ))

    passw = Request("pass", children=(
        String(name="key", default_value="PASS", fuzzable=False),
        Delim(name="space", default_value=" ", fuzzable=True),
        String(name="val", default_value="james", fuzzable=True),
        Static(name="end", default_value="\r\n"),
    ))

    session.connect(user)
    session.connect(user, passw)


if __name__ == "__main__":
    main()
