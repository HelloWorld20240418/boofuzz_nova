
from boofuzz import *


def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("192.168.1.200", 80)),
        fuzz_db_keep_only_n_pass_cases=10,
        index_end=100,
        sleep_time=1,
        keep_web_open=False,    #session结束后保持web端口可访问
    )

    define_proto(session=session)

    session.fuzz(max_depth=1)

'''
max_depth=1：仅变异单个字段（如 Method、Path、Data），不组合。
max_depth=2：允许 2 个字段组合变异（如 Method+Path 或 Path+Data）。
max_depth=None：所有字段自由组合（如 Method+Path+Data）
'''

def define_proto(session):

    req = Request("HTTP-Request", children=(
        Block("Request-Line", children=(
            Group(name="Method", values=["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"]),
            String(name="URI", default_value="/index.html"),
            Static(name="HTTP-Version", default_value=" HTTP/1.1"),
            Static(name="CRLF", default_value="\r\n\r\n"),
        )),
    ))

    session.connect(req)

if __name__ == "__main__":
    main()

