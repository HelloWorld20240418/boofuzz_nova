
from boofuzz import *

host_ip = '192.168.16.254'
host_port = 80


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),
                      keep_web_open=False
                      )
    fuzzing_http_request(session=session)
    session.fuzz(max_depth=1)

def fuzzing_http_request(session):

    # 定义 WebSocket 握手请求
    s_initialize(name="websocket_handshake")
    s_static("GET /websocket HTTP/1.1\r\n")
    s_static("Host: host_ip\r\n")
    s_static("Upgrade: websocket\r\n")
    s_static("Connection: Upgrade\r\n")
    s_static("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")  # 固定或动态生成
    s_static("Sec-WebSocket-Version: 13\r\n\r\n")

    # 定义 WebSocket 数据帧
    s_initialize(name="websocket_frame")
    with s_block("frame_header"):
        s_byte(0x81, name="fin_and_opcode", fuzzable=False)  # 默认文本帧（0x81），模糊操作码
        s_byte(0x80, name="mask_and_length", fuzzable=False)  # 掩码位 + 长度
        s_size("Masked_payload", output_format="ascii", length=2, name="extended_length", fuzzable=False)
        s_random(name="mask_key", min_length=4, max_length=4, num_mutations=10, fuzzable=False)  # 随机掩码密钥

    # 负载数据
    with s_block("Masked_payload"):
        s_string(value='{"param":{"uid":"1186375284","uuid":"PSVD-JqteO2Bt9O2BecgSD2t6JT2rlwO3DO3D"},"wsToken":"PSVD-JqteO2Bt9O2BecgSD2t6JT2rlwO3DO3D","plat":"miguzhibo","type":1,"compressType":1,"userType":0}', name="payload", fuzzable=True)  # 模糊负载内容

    # 定义测试顺序：先握手，后发送数据帧
    session.connect(s_get("websocket_handshake"))
    session.connect(s_get("websocket_handshake"), s_get("websocket_frame"))

    # 启动模糊测试
    session.fuzz()

if __name__ == "__main__":
    fuzzing_main()
