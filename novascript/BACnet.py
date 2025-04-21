
host_ip = ''
host_port = 47808

def fuzzing_main():
        session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param )

        fuzzing_define_bvlc(session=session)

        session.fuzz()
    # 定义BVLC层（BACnet虚拟链路控制）
def fuzzing_define_bvlc(session):
        s_initialize("bvlc")
        s_byte(0x81, name="type")  # BACnet/IP广播类型
        s_byte(0x0a, name="function")  # 原始报文传输
        s_word(0x0000, name="length")  # 占位符，后续更新

    # 定义NPDU层（网络协议数据单元）

        s_initialize("npdu")
        s_byte(0x01, name="version")  # BACnet版本1
        s_byte(0x20, name="control")  # 包含源地址和目标地址
        s_bytes(b"\x00\x00", name="dst_address")  # 空目标地址
        s_bytes(b"\x01\x00\x01", name="src_address")  # 源地址示例
        s_byte(0x00, name="hop_count")

    # 定义APDU层（应用协议数据单元）

        s_initialize("apdu")
        s_byte(0x00, name="pdu_type")  # 未确认服务请求
        s_byte(0x0c, name="service_choice")  # ReadProperty服务

        # 对象标识符（设备对象）
        s_bytes(b"\xc0\x04\x00\x08", name="object_id")  # 类型8（设备），实例1

        # 属性标识符（对象名称）
        s_bytes(b"\x19\x22", name="property_id")

    # 定义测试流程
        session.connect(s_get("bvlc"))




if __name__ == "__main__":
        fuzzing_main()
