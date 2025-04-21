
host_ip = ''
host_port = 465

def fuzzing_main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    connection = SSLSocketConnection(host_ip, host_port, sslcontext=context)
    session = Session(target=Target(connection),nova_session_param=nova_session_param )


    # 定义协议消息格式
    def define_smtp_command(name, prefix, fuzz_field):
        s_initialize(name)
        s_static(prefix)  # 固定命令前缀
        s_string(fuzz_field, name=name)  # 可模糊字段
        s_static("\r\n")  # 协议换行符

    # EHLO命令
    define_smtp_command("EHLO", "EHLO ", "testclient")

    # MAIL FROM命令
    define_smtp_command("MAIL_FROM", "MAIL FROM:<", "sender@example.com")
    s_static(">")  # 闭合邮箱地址

    # DATA命令
    s_initialize("DATA")
    s_static("DATA\r\n")
    s_string("This is a fuzzed message body!", name="email_body")
    s_static("\r\n.\r\n")  # 邮件结束标记

    # 设置测试流程
    session.connect(s_get("EHLO"))  # 初始连接
    session.connect(s_get("EHLO"), s_get("MAIL_FROM"))
    session.connect(s_get("MAIL_FROM"), s_get("DATA"))

    # 启动模糊测试
    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()
