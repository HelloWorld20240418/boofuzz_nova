from boofuzz import *
import socket




def main():
# 配置Boofuzz会话
    session = Session(
            target=Target(connection=TCPSocketConnection("192.168.1.200", 80)),
            fuzz_db_keep_only_n_pass_cases=10,
            index_end=100,
            sleep_time=1,
            keep_web_open=False,    #session结束后保持web端口可访问
            post_test_case_callbacks=[monitor_80_port_health]
        )
# 定义测试用例
    s_initialize("HTTP Test")
    s_string("GET", name="method")
    s_delim(" ", name="space1")
    s_string("/index.html", name="path")
    s_static("\r\n\r\n")

    session.connect(s_get("HTTP Test"))
    session.fuzz()


def monitor_80_port_health(target, logger, test_case, *args, **kwargs):

    target_ip = target.get_connection().host  # 获取目标IP
    port = 80
    timeout = 3  # 检测超时时间(秒)

    logger.log_info(f"正在检查目标 {target_ip}:{port} 的健康状态...")

    try:
        # 创建新的socket连接测试端口
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))

        # 可选：发送基础HTTP请求验证服务
        sock.send(b"GET / HTTP/1.1\r\nHost: %b\r\n\r\n" % target_ip.encode())
        response = sock.recv(1024)

        if response:
            logger.log_pass(f"目标服务正常 (响应长度: {len(response)} 字节)")
        else:
            logger.log_warn("收到空响应，服务可能异常")

    except socket.timeout:
        logger.log_fail(f"连接超时，目标服务无响应 (超时: {timeout}秒)")
    except ConnectionRefusedError:
        logger.log_fail("连接被拒绝，服务可能已崩溃")
    except Exception as e:
        logger.log_fail(f"健康检查失败: {str(e)}")
    finally:
        sock.close()  # 确保关闭临时连接



if __name__ == "__main__":
    main()
