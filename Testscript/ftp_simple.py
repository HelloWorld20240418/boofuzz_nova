
from boofuzz import *


def main():
 
    session = Session(target=Target(connection=TCPSocketConnection("192.168.1.200", 21)),
                      index_start=12000,
                      index_end=12002)

    define_proto(session=session)

    session.fuzz()


def define_proto(session):

    user = Request("user", children=(
        String(name="key", default_value="USER"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="anonymous"),
        Static(name="end", default_value="\r\n"),
    ))

    passw = Request("pass", children=(
        String(name="key", default_value="PASS"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="james"),
        Static(name="end", default_value="\r\n"),
    ))

    stor = Request("stor", children=(
        String(name="key", default_value="STOR"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="AAAA"),
        Static(name="end", default_value="\r\n"),
    ))

    retr = Request("retr", children=(
        String(name="key", default_value="RETR"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="AAAA"),
        Static(name="end", default_value="\r\n"),
    ))

    session.connect(user)
    session.connect(user, passw)
    session.connect(passw, stor)
    session.connect(passw, retr)


if __name__ == "__main__":
    main()
