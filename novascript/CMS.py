host_ip = ''
host_port = 8102

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    #关联服务
    fuzzing_cms_Associate(session=session)#关联，服务码1
    fuzzing_Abort(session=session)#异常中止，服务码2
    fuzzing_Release(session=session)#释放，服务码3
    #模型和数据服务
    fuzzing_GerserverDirectory(session=session)#读服务器目录，服务码80
    fuzzing_GetLogicDeviceDirectory(session=session)#读逻辑设备目录，服务码81
    fuzzing_GetLoggicNodeDirectory(session=session)  # 读逻辑节点目录,服务码82
    fuzzing_cms_GetAllDataValues(session=session), #服务码83
    fuzzing_GetAllDataDefinition(session=session)#读所有数据定义，服务码155
    fuzzing_GetAllCBValues(session=session)#读所有控制块值，服务码156
    fuzzing_GetDataValues(session=session)#读数据值，服务码48
    fuzzing_SetDataValues(session=session)#设置数据值，服务码49
    fuzzing_GetDataDirectory(session=session)#读数据目录,，服务码50
    fuzzing_GetDataDefinition(session=session)#读数据定义，服务码51
    #数据集服务
    fuzzing_GetDateSetDirectory(session=session)#读取数据集目录，服务码57
    #控制服务
    fuzzing_cms_SelectWithValue(session=session)#带值选择,服务码69
    fuzzing_Cancel(session=session)# 取消,服务码70
    fuzzing_OPERATE(session=session)#执行,服务码71
    #定值组服务
    fuzzing_SelectActiveSG(session=session)#选择激活定值组，服务码84
    fuzzing_SelectEditSG(session=session)#选择编辑定值组，服务码85
    fuzzing_SetEditSGValue(session=session)#选择编辑定值组，服务码86
    fuzzing_ConfirmEditSGValiues(session=session)#确认编辑定值组值，服务码87
    fuzzing_GetEditSGValue(session=session)#读编辑定值组值，服务码88
    fuzzing_GetSGCBValues(session=session)#读定值组控制块值，服务码89
    #报告服务
    fuzzing_Report(session=session)#报告，服务码90
    fuzzing_GetBRCBValues(session=session)#读缓存报告控制块值，服务码91
    fuzzing_SetBRCBValues(session=session)#设置缓存报告控制块值，服务码92
    fuzzing_GetURCBValues(session=session)#读非缓存报告控制块值，服务码93
    fuzzing_SetUrcBValues(session=session)#设置非缓存报告控制块值，服务码94
    #日志服务
    fuzzing_GetLCBValues(session=session)#读日志控制块值服务码95
    fuzzing_SetLCBValues(session=session)# 设置日志控制块值，服务码96
    fuzzing_QueryLogByTime(session=session)#按时间查询日志.服务码97
    fuzzing_QueryLogAfter(session=session)# 查询指定条目之后的日志,服务码98
    fuzzing_GetLogStatusValues(session=session)#读日志状态值，服务码99
    #文件服务
    fuzzing_GetFile(session=session)#读文件，服务码128
    # fuzzing_GetFileDirectory(session=session)#列文件目录，服务码132
    #远程过程调用
    fuzzing_GetRpcInterfaceDirectory(session=session)# 读远程调用接口目录，服务码110
    #测试
    fuzzing_Test(session=session)#测试,服务码153
    #关联协商
    fuzzing_cms_AssociateNegotiate(session=session)   #关联协商，服务码154

    session.fuzz()


def fuzzing_cms_Associate(session):#关联，服务码1
        s_initialize(name="Associate")
        with s_block("APCH"):
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='SC', fuzzable=False)
            s_bytes(value=bytes([0X14, 0X00]), size=2, max_len=2, name='FL', fuzzable=False)
        with s_block("ASDU"):
            s_bytes(value=bytes([0X20, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
            s_bytes(value=bytes([0X84, 0x00, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54, 0x31,
                                 0x47, 0x5a, 0x4b, 0x2e, 0x53, 0x31]), size=18, max_len=18, name='associate',
                    fuzzable=True)
        session.connect(s_get('Associate'))


def fuzzing_Abort(session):# 异常中止，服务码2
    s_initialize(name="QAbort")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x0c, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x10,0x48,0x09,0x00,0x00,0x00,0x00,0x00,0x00]), size=9, max_len=9,name='associationID', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reason', fuzzable=False)
    session.connect(s_get('QAbort'))

def fuzzing_Release(session):  # 释放，服务码3
    s_initialize(name="Release")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x0b, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x03, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=9, max_len=9,
                name='associationId', fuzzable=True)
    session.connect(s_get('Release'))
    # 读服务器目录，服务码80
def fuzzing_GerserverDirectory(session):
        s_initialize(name="GerserverDirectory")
        with s_block("Spirent_test_center_signature"):
            s_bytes(value=bytes([0x16, 0x80, 0x18, 0x00, 0xe5, 0x82, 0x5d, 0x00, 0x00, 0x01, 0x01, 0x08
                                    , 0x0a, 0x0a, 0x42, 0x36, 0xab, 0x03, 0xc3, 0x41]), size=20, max_len=20,
                    name='raw_data', fuzzable=False)
        with s_block("APCH"):
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
            s_bytes(value=bytes([0x50]), size=1, max_len=1, name='SC', fuzzable=False)
            s_bytes(value=bytes([0X03, 0X00]), size=2, max_len=2, name='FL', fuzzable=False)
        with s_block("ASDU"):
            s_bytes(value=bytes([0X03, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
            s_bytes(value=bytes([0X20]), size=1, max_len=1, name='GerserverFirectory', fuzzable=False)
        # 新增
        with s_block("STCS"):
            s_bytes(value=bytes([0X16]), size=1, max_len=1, name='IV', fuzzable=False)
            s_bytes(value=bytes([0Xec, 0x24]), size=2, max_len=2, name='ChassisSlotPort', fuzzable=False)
            s_bytes(value=bytes([0Xe1, 0xba]), size=2, max_len=2, name='Stream_Index', fuzzable=False)
            s_bytes(value=bytes([0x67, 0xb4, 0x43, 0x76, 0xfb, 0xe9]), size=6, max_len=6, name='Sequence_number',
                    fuzzable=False)
            s_bytes(value=bytes([0x3a, 0xa2, 0xdc, 0x72, 0x7d, ]), size=5, max_len=5, name='timestamp', fuzzable=False)
            s_bytes(value=bytes([0Xab, 0x03, 0xc3, 0x41]), size=4, max_len=4, name='Unknown', fuzzable=True)
        session.connect(s_get('GerserverDirectory'))
    # 读逻辑设备目录，服务码81
def fuzzing_GetLogicDeviceDirectory(session):
        s_initialize(name="GetLogicDeviceDirectory")
        with s_block("APCH"):
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
            s_bytes(value=bytes([0x51]), size=1, max_len=1, name='SC', fuzzable=False)
            s_bytes(value=bytes([0X14, 0X00]), size=2, max_len=2, name='FL', fuzzable=False)
        with s_block("ASDU"):
            s_bytes(value=bytes([0X04, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
            s_bytes(value=bytes([0x88,0x00,0x50,0x41,0x43,0x53,0x35,0x39,0x34,0x31,
                                 0x54,0x31,0x47,0x5a,0x4b,0x4c,0x44,0x30]), size=18, max_len=18, name='IdName', fuzzable=True)
        session.connect(s_get('GetLogicDeviceDirectory'))

    # 读逻辑节点目录,服务码82
def fuzzing_GetLoggicNodeDirectory(session):
    s_initialize(name="GetLoggicNodeDirectory")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x52]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x16, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0xaf, 0x01]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x08, 0x80, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54, 0x31, 0x47
                                , 0x5a, 0x4b, 0x50, 0x52, 0x4f, 0x54]), size=19, max_len=19,
                name='GetLoggicNodeDirectory', fuzzable=True)
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name='acsiclass', fuzzable=False)
    session.connect(s_get('GetLoggicNodeDirectory'))

    # 读所有数据定义，服务码155
def fuzzing_GetAllDataDefinition(session):
    s_initialize(name="GetAllDataDefinition")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x9b]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x19, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x08, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x22, 0xa0, 0x50, 0x41, 0x43, 0x53, 0x35, 0x35, 0x34, 0x31, 0x54, 0x31, 0x47
                                , 0x5a, 0x4b, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x4c, 0x4e, 0x30]), size=23, max_len=23,
                name='GetAllDataDefinition', fuzzable=True)
    session.connect(s_get('GetAllDataDefinition'))

    # 读所有数据值,服务码83
def fuzzing_cms_GetAllDataValues(session):
    s_initialize(name="cms_GetAllDataValues")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x53]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x18, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x25, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x80, 0x54, 0x45, 0x4d, 0x50, 0x4c, 0x41, 0x54, 0x45
                                , 0x4c, 0x44, 0x30, 0x2f, 0x41, 0x6c, 0x6d,0x47,0x47,0x49,0x4f,0x36]), size=22, max_len=22,
                name='cms_GetAllDataValues', fuzzable=False)
    s_bytes(value=bytes([0x20]), size=1, max_len=1, name='acsiclass', fuzzable=False)
    session.connect(s_get('cms_GetAllDataValues'))

    # 读所有控制块值，服务码156
def fuzzing_GetAllCBValues(session):
    s_initialize(name="GetAllCBValues")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x9c]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x2d, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x6f, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x85,0x80,0x54,0x45,0x4d,0x50,0x4c,0x41,0x54,0x45,0x4c,0x44,0x30]), size=13, max_len=13,
                name='IdName', fuzzable=False)
        s_bytes(value=bytes([0x31,0xc0,0x54,0x45,0x4d,0x50,0x4c,0x41,0x54,0x45
                            ,0x4c,0x44,0x30,0x2f,0x4c,0x4c,0x4e,0x30,0x2e,0x62,
                             0x72,0x63,0x62,0x41,0x6c,0x61,0x72,0x6d,0x30,0x31
                             ]), size=30, max_len=30,name='referenceAfter', fuzzable=True)

    session.connect(s_get('GetAllCBValues'))

    # 读数据值，服务码48
def fuzzing_GetDataValues(session):
    s_initialize(name="GetDataValues")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x30]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0X14, 0X00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0X20, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0X84, 0x00, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54, 0x31,
                             0x47, 0x5a, 0x4b, 0x2e, 0x53, 0x31]), size=18, max_len=18, name='associate',
                fuzzable=True)
    session.connect(s_get('GetDataValues'))



    # 选择设置数据值,服务码49
def fuzzing_SetDataValues(session):
        s_initialize(name="SetDataValues")
        with s_block("APCH"):
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
            s_bytes(value=bytes([0x31]), size=1, max_len=1, name='SC', fuzzable=False)
            s_bytes(value=bytes([0xb3, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
        with s_block("ASDU"):
            s_bytes(value=bytes([0x21, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='data_header', fuzzable=False)
            s_bytes(value=bytes([0x90, 0x80, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31,
                                 0x54, 0x31, 0x47, 0x5a, 0x4b, 0x50, 0x52, 0x4f, 0x54, 0x2f,
                                 0x48, 0x50, 0x54, 0x4d, 0x4d, 0x58, 0x55, 0x31, 0x2e, 0x41,
                                 0x2e, 0x70, 0x68, 0x73, 0x41]), size=35, max_len=35,
                    name='reference', fuzzable=True)
            s_bytes(value=bytes([0x58, 0x58]), size=2, max_len=2, name='fc', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x11, 0x10, 0x02, 0x10, 0x01]), size=6, max_len=6, name='structure1_header_1_1',
                    fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_1_1', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x01]), size=2, max_len=2, name='structure1_header_1_2', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_1_2', fuzzable=False)
            s_bytes(value=bytes([0xa0, 0x00]), size=2, max_len=2, name='structure_2', fuzzable=False)
            s_bytes(value=bytes([0x24, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='secondsinceepoc',
                    fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='fractionofsecond', fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Timequalit', fuzzable=False)
            s_bytes(value=bytes([0x18]), size=1, max_len=1, name='boolean', fuzzable=False)
            s_bytes(value=bytes([0x40, 0x02, 0x10, 0x01]), size=4, max_len=4, name='structure1_header_5_1',
                    fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_5_1', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x01]), size=2, max_len=2, name='structure1_header_5_2', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_5_2', fuzzable=False)
            s_bytes(value=bytes([0xa0, 0x00]), size=2, max_len=2, name='structure_6', fuzzable=False)
            s_bytes(value=bytes([0x20, 0x00]), size=2, max_len=2, name='visible_string', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x02]), size=2, max_len=2, name='structure1_header_8_1', fuzzable=False)
            s_bytes(value=bytes([0x20, 0x80]), size=2, max_len=2, name='int8_1', fuzzable=False)
            s_bytes(value=bytes([0x20, 0x80]), size=2, max_len=2, name='int8_2', fuzzable=False)
            s_bytes(value=bytes([0x50, 0x01, 0x00]), size=3, max_len=3, name='int32u_9', fuzzable=False)
            s_bytes(value=bytes([0x50, 0x01, 0x00]), size=3, max_len=3, name='int32u_10', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x06]), size=2, max_len=2, name='11_header', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x01]), size=2, max_len=2, name='structure1_header_11_1', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_11_1', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x01]), size=2, max_len=2, name='structure1_header_11_2', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_11_2', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x01]), size=2, max_len=2, name='structure1_header_11_3', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_11_3', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x01]), size=2, max_len=2, name='structure1_header_11_4', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_11_4', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x01]), size=2, max_len=2, name='structure1_header_11_5', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_11_5', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x01]), size=2, max_len=2, name='structure1_header_11_6', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_11_6', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x02]), size=2, max_len=2, name='structure1_header_12_1', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_12_1', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_12_2', fuzzable=False)
            s_bytes(value=bytes([0x10, 0x02]), size=2, max_len=2, name='structure1_header_13_1', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_13_1', fuzzable=False)
            s_bytes(value=bytes([0x60, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='float32_13_2', fuzzable=False)
            s_bytes(value=bytes([0x20, 0x80]), size=2, max_len=2, name='int8_14', fuzzable=False)
            s_bytes(value=bytes([0x50, 0x01, 0x00]), size=3, max_len=3, name='int32u_15', fuzzable=False)
            s_bytes(value=bytes([0x80, 0x00]), size=2, max_len=2, name='visible_string_16', fuzzable=False)
            s_bytes(value=bytes([0x88, 0x00]), size=2, max_len=2, name='visible_string_17', fuzzable=False)
        session.connect(s_get('SetDataValues'))

# 读数据目录,服务码50
def fuzzing_GetDataDirectory(session):
    s_initialize(name="GetDataDirectory")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x32]), size=1, max_len=1, name='CS', fuzzable=False)
        s_bytes(value=bytes([0X1e, 0X00]), size=2, max_len=2, name='FL', fuzzable=True)
    with s_block("ASDU"):
        s_bytes(value=bytes([0X09, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes(
            [0x0d, 0x00, 0x50, 0x41, 0x43, 0x53, 0x35, 0x37, 0x31, 0x31,
             0x41, 0x47, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x50, 0x48, 0x44,
             0x31, 0x2e, 0x52, 0x73, 0x53, 0x74, 0x61, 0x74
             ]), size=28,
            max_len=34, name='GetDataDirectory', fuzzable=False)
    session.connect(s_get('GetDataDirectory'))

    # 读数据定义,服务码51
def fuzzing_GetDataDefinition(session):
        s_initialize(name="GetDataDefinition")
        with s_block("APCH"):
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
            s_bytes(value=bytes([0x33]), size=1, max_len=1, name='CS', fuzzable=False)
            s_bytes(value=bytes([0X20, 0X00]), size=2, max_len=2, name='FL', fuzzable=True)
        with s_block("ASDU"):
            s_bytes(value=bytes([0X52, 0x02]), size=2, max_len=2, name='ReqID', fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CS', fuzzable=False)
            s_bytes(value=bytes(
                [0x0d, 0x80, 0x54, 0x45, 0x4d, 0x50, 0x4c, 0x41, 0x54, 0x45,
                 0x4d, 0x45, 0x41,0x53,0x2f,0x52,0x73,0x79,0x6e,0x4d,
                 0x4d,0x58,0x4e,0x31,0x2e,0x56,0x6f,0x6c,0x34
                 ]), size=29,
                    max_len=29, name='reference', fuzzable=True)
        session.connect(s_get('GetDataDefinition'))

    #读取数据集目录，服务码57
def fuzzing_GetDateSetDirectory(session):
    s_initialize(name="GetDateSetDirectory")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x39]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x25, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0xeb, 0x01]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x10, 0x80, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31,
                             0x54, 0x31, 0x47, 0x5a, 0x4b, 0x50, 0x52, 0x4f, 0x54, 0x2f,
                             0x4c, 0x4c, 0x4e, 0x30, 0x2e, 0x64, 0x53, 0x73, 0x65, 0x74,
                             0x74, 0x69, 0x6e, 0x67, 0x37]), size=35, max_len=35,
                name='reference', fuzzable=True)
    session.connect(s_get('GetDateSetDirectory'))



    # 带值选择,服务码69
def fuzzing_cms_SelectWithValue(session):
        s_initialize(name="cms_SelectWithValue")
        with s_block("APCH"):
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
            s_bytes(value=bytes([0x45]), size=1, max_len=1, name='CS', fuzzable=False)
            s_bytes(value=bytes([0X34, 0X00]), size=2, max_len=2, name='FL', fuzzable=True)
        with s_block("ASDU"):
            s_bytes(value=bytes([0X3f, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
            s_bytes(value=bytes(
                [0x10, 0x00, 0x50, 0x41, 0x43, 0x53, 0x35, 0x37, 0x37, 0x36, 0x44, 0x44, 0x4d, 0x31, 0x5a, 0x4b, 0x43,
                 0x54, 0x52, 0x4c,
                 0x2f, 0x41, 0x54, 0x43, 0x43, 0x31, 0x2e, 0x54, 0x61, 0x70, 0x43, 0x68, 0x67, 0x41]), size=34,
                    max_len=34, name='reference', fuzzable=False)
            s_bytes(value=bytes([0xb4]), size=1, max_len=1, name='tcnd', fuzzable=False)
            s_bytes(value=bytes([0x40, 0xc0, 0x64, 0x66, 0x65]), size=5, max_len=5, name='orIdent', fuzzable=False)
            s_bytes(value=bytes([0x20]), size=1, max_len=1, name='ctlNum', fuzzable=False)
            s_bytes(value=bytes([0x62, 0xbd, 0x44, 0x2a]), size=4, max_len=4, name='SecondsinceEpoc', fuzzable=False)
            s_bytes(value=bytes([0x9a, 0x47, 0x8b]), size=3, max_len=3, name='FractionOfSecond', fuzzable=False)
            s_bytes(value=bytes([0x0a]), size=1, max_len=1, name='timequalit', fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='test', fuzzable=False)
        session.connect(s_get('cms_SelectWithValue'))

# 取消,服务码70
def fuzzing_Cancel(session):
    s_initialize(name="Cancel")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x46]), size=1, max_len=1, name='CS', fuzzable=False)
        s_bytes(value=bytes([0X2d, 0X00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0X12, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes(
            [0x0e, 0x00, 0x50, 0x41, 0x43, 0x53, 0x35, 0x37, 0x31, 0x31, 0x41, 0x47, 0x50, 0x52, 0x4f, 0x54, 0x2f,
             0x4c, 0x4c, 0x4e,
             0x30, 0x2e, 0x46, 0x75, 0x6e, 0x63, 0x45, 0x6e, 0x61, 0x31]), size=30,
            max_len=30, name='reference', fuzzable=True)
        s_bytes(value=bytes([0x1c]), size=1, max_len=1, name='ctlVal', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='orIdent', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='ctlNum', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00,0x00]), size=4, max_len=4, name='SecondsinceEpoc', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='FractionOfSecond', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='timequalit', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='test', fuzzable=False)
    session.connect(s_get('Cancel'))


    #执行,服务码71
def fuzzing_OPERATE(session):
    s_initialize(name="OPERATE")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x47]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0X33, 0X00]), size=2, max_len=2, name='FL', fuzzable=True)
    with s_block("ASDU"):
        s_bytes(value=bytes([0X40, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes(
            [0x20, 0x50, 0x41, 0x43, 0x53, 0x35, 0x37, 0x37, 0x36, 0x44, 0x44, 0x4d, 0x31, 0x5a, 0x4b, 0x43,
             0x54,
             0x52, 0x4c, 0x2f, 0x41, 0x54, 0x43, 0x43, 0x31, 0x2e, 0x54, 0x61, 0x70, 0x43, 0x68, 0x67, 0x41]),
            size=34, max_len=34,
            name='reference', fuzzable=False)
        s_bytes(value=bytes([0xb4]), size=1, max_len=1, name='tcnd', fuzzable=False)
        s_bytes(value=bytes([0x40, 0xc0, 0x64, 0x66, 0x65]), size=5, max_len=5, name='orIdent', fuzzable=False)
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name='ctlNum', fuzzable=False)
        s_bytes(value=bytes([0x62, 0xbd, 0x44, 0x2a]), size=4, max_len=4, name='SecondsinceEpoc',
                fuzzable=False)
        s_bytes(value=bytes([0xa2, 0x7f, 0x76]), size=3, max_len=3, name='FractionOfSecond', fuzzable=False)
        s_bytes(value=bytes([0x0a]), size=1, max_len=1, name='timequalit', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='test', fuzzable=False)
    session.connect(s_get('OPERATE'))
    # 选择激活定值组，服务码84
def fuzzing_SelectActiveSG(session):
    s_initialize(name="SelectActiveSG")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x54]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x1f, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x4f, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x1b, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54,
                             0x31, 0x47, 0x5a, 0x4b, 0x50, 0x52, 0x4f, 0x54, 0x2f, 0x4c,
                             0x4c, 0x4e, 0x30, 0x2e, 0x53, 0x47, 0x43, 0x42]), size=28, max_len=28,
                name='reference', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='SGN', fuzzable=False)
    session.connect(s_get('SelectActiveSG'))

    # 选择编辑定值组，服务码85
def fuzzing_SelectEditSG(session):
    s_initialize(name="SelectEditSG")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x55]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x1f, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x83, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x1b, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54,
                             0x31, 0x47, 0x5a, 0x4b, 0x50, 0x52, 0x4f, 0x54, 0x2f, 0x4c,
                             0x4c, 0x4e, 0x30, 0x2e, 0x53, 0x47, 0x43, 0x42]), size=28, max_len=28,
                name='reference', fuzzable=True)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='SGN', fuzzable=False)
    session.connect(s_get('SelectEditSG'))

        # 选择编辑定值组，服务码86

def fuzzing_SetEditSGValue(session):
    s_initialize(name="SetEditSGValue")
    with s_block("APCH"):
        s_bytes(value=bytes([0x41]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x56]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0xe8, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='header', fuzzable=False)
        s_bytes(value=bytes([0x28, 0x50, 0x41, 0x43, 0x53, 0x35, 0x37, 0x31, 0x31, 0x41,
                             0x47, 0x50,  0x52, 0x4f, 0x54, 0x2f, 0x50,0x68,0x50
                             ,0x54,0x4f,0x43,0x31,0x2e,0x53,0x74,0x72,0x56,0x61,0x6c
                            ,0x2e,0x73,0x74,0x65,0x70,0x53,0x69,0x7a,0x65,0x2e,0x66]), size=41, max_len=41,
                name='reference', fuzzable=True)
        s_bytes(value=bytes([0x60,0x00,0x00,0x00,0x00]), size=5, max_len=5, name='Float', fuzzable=False)
    session.connect(s_get('SetEditSGValue'))


    # 确认编辑定值组值，服务码87
def fuzzing_ConfirmEditSGValiues(session):
    s_initialize(name="ConfirmEditSGValiues")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x57]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x1e, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x4c, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x1b, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54,
                             0x31, 0x47, 0x5a, 0x4b, 0x50, 0x52, 0x4f, 0x54, 0x2f, 0x4c,
                             0x4c, 0x4e, 0x30, 0x2e, 0x53, 0x47, 0x43, 0x42]), size=28, max_len=28,
                name='reference', fuzzable=True)
    session.connect(s_get('ConfirmEditSGValiues'))

# 读定值组控制块值，服务码88
def fuzzing_GetEditSGValue(session):
    s_initialize(name="GetEditSGValue")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x58]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x2c, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x4f, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='urcb', fuzzable=False)
        s_bytes(value=bytes([0x26, 0x50, 0x41, 0x43, 0x53, 0x35, 0x37, 0x31, 0x31, 0x41,
                            0x47, 0x50, 0x52, 0x4f, 0x54, 0x2f, 0x50, 0x68, 0x50,0x54,
                             0x4f,0x43,0x31,0x2e,0x53,0x74,0x72,0x56,0x61,0x6c,
                             0x2e,0x73,0x65,0x74,0x4d,0x61,0x67,0x2e,0x66]), size=39, max_len=39,
                name='reference', fuzzable=True)
        s_bytes(value=bytes([0x53, 0x47]), size=2, max_len=2, name='FC', fuzzable=False)
    session.connect(s_get('GetEditSGValue'))

    #读定值组控制块值，服务码89
def fuzzing_GetSGCBValues(session):
    s_initialize(name="GetSGCBValues")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x59]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x1f, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x24, 0x02]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='urcb', fuzzable=False)
        s_bytes(value=bytes([0x1b, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54,
                             0x31, 0x47, 0x5a, 0x4b, 0x50, 0x52, 0x43, 0x4f, 0x54, 0x2f,
                             0x4c, 0x4c, 0x4e, 0x30, 0x2e, 0x53, 0x47, 0x43, 0x42]), size=28, max_len=28,
                name='reference', fuzzable=True)
    session.connect(s_get('GetSGCBValues'))

    # 报告，服务码90
def fuzzing_Report(session):
    s_initialize(name="Report")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x5a]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x8c, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x9c, 0x68, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x4c, 0x4e, 0x30,
                             0x2e, 0x62, 0x72, 0x63, 0x62, 0x44, 0x65, 0x76, 0x69, 0x63,
                             0x65,0x53,0x74,0x61,0x74,0x65,0x30,0x31]), size=28, max_len=28,name='rptID', fuzzable=False)
        s_bytes(value=bytes([0x7f]), size=1, max_len=1, name='optFlds', fuzzable=False)
        s_bytes(value=bytes([0x80, 0x00, 0x01]), size=3, max_len=3, name='sqnum', fuzzable=False)
        s_bytes(value=bytes([0x25, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54,
                             0x31, 0x47, 0x5a, 0x4b, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x4c,
                             0x4e, 0x30, 0x2e, 0x64, 0x73, 0x44, 0x65, 0x76,0x69,0x63,
                             0x65,0x53,0x74,0x61,0x74,0x65]), size=36, max_len=36,name='detset', fuzzable=True)
        s_bytes(value=bytes([0x00,0x01, 0x01]), size=3, max_len=3, name='confrev', fuzzable=False)
        s_bytes(value=bytes([0xc0, 0x00, 0x68, 0x8e, 0x1f]), size=5, max_len=5, name='ms', fuzzable=False)
        s_bytes(value=bytes([0x36, 0x5f]), size=2, max_len=2, name='days', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=8, max_len=8, name='entryID', fuzzable=False)
        s_bytes(value=bytes([0xe3, 0xc0, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31,
                             0x54, 0x31, 0x47, 0x5a, 0x4b, 0x4c, 0x44, 0x30, 0x2f, 0x53,
                             0x74, 0x61, 0x47, 0x47,0x49, 0x4f,0x31,0x2e,0x49,0x6e,0x64,0x35,]), size=32, max_len=32,
                name='reference', fuzzable=False)
        s_bytes(value=bytes([0x53, 0x54]), size=2, max_len=2, name='fc', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x05]), size=2, max_len=2, name='id', fuzzable=False)
        s_bytes(value=bytes([0x10, 0x03,]), size=2, max_len=2, name='value_header', fuzzable=False)
        s_bytes(value=bytes([0x1e]), size=1, max_len=1, name='boolean', fuzzable=False)
        s_bytes(value=bytes([0x60, 0xc1, 0x8d, 0x99, 0x9a]), size=5, max_len=5, name='float32', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='validity', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='outofrange', fuzzable=False)
        s_bytes(value=bytes([0x90, 0x62, 0x03, 0x1e, 0xc4]), size=5, max_len=5, name='secondsinceepoc',
                fuzzable=False)
        s_bytes(value=bytes([0x1b, 0x98, 0xb0]), size=3, max_len=3, name='Fractionofsecond', fuzzable=False)
        s_bytes(value=bytes([0x6a]), size=1, max_len=1, name='timequalit', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='reserved', fuzzable=False)

    session.connect(s_get('Report'))


    #读缓存报告控制块值，服务码91
def fuzzing_GetBRCBValues(session):
    s_initialize(name="GetBRCBValues")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x5b]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x2a, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x0e, 0x02]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x01]), size=2, max_len=2, name='header', fuzzable=False)
        s_bytes(value=bytes([0x04,0x60, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31,0x54,
                             0x31, 0x47, 0x5a, 0x4b, 0x4c,0x44,0x30, 0x2f, 0x4c, 0x4c,
                             0x4e,0x30, 0x2e,0x62, 0x72, 0x63, 0x62,0x57,0x61,0x72,
                             0x6e,0x69,0x6e,0x67,0x30,0x31]),size=37, max_len=37,name='reference', fuzzable=True)
        s_bytes(value=bytes([0x80]),size=1, max_len=1,name='gi', fuzzable=True)
        session.connect(s_get('GetBRCBValues'))


        # 设置缓存报告控制块值，服务码92
def fuzzing_SetBRCBValues(session):
    s_initialize(name="SetBRCBValues")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x5c]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x32, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x10, 0x02]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='urcb', fuzzable=False)
        s_bytes(value=bytes([0x44, 0x80, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31,
                             0x54, 0x31, 0x47, 0x5a, 0x4b, 0x52, 0x43, 0x44, 0x2f, 0x4c, 0x4c, 0x4e, 0x30, 0x2e,
                             0x62, 0x72, 0x63, 0x62, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x52, 0x65, 0x63, 0x30, 0x31]),
                size=38, max_len=38,
                name='reference', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='entryID',
                fuzzable=False)
    session.connect(s_get('SetBRCBValues'))

    #读非缓存报告控制块值，服务码93
def fuzzing_GetURCBValues(session):
    s_initialize(name="GetURCBValues")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x5d]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x49, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0xd8, 0x01]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='header', fuzzable=False)
        s_bytes(value=bytes([0x1f,0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54,
                             0x31, 0x47, 0x5a, 0x4b, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x4c,
                             0x4e, 0x30, 0x2e, 0x75, 0x72,0x63, 0x62,0x41, 0x69, 0x6e,
                             0x30, 0x31]), size=32, max_len=32,
                name='reference1', fuzzable=True)
        s_bytes(value=bytes([0x25,0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54,
                             0x31, 0x47, 0x5a, 0x4b, 0x50,0x52,0x4f,0x54,0x2f, 0x4c,
                             0x4c,0x4e, 0x30, 0x2e, 0x75, 0x72,0x63, 0x62,0x52,0x65,
                             0x6c,0x61,0x79,0x41, 0x69,0x6e,0x30, 0x31]), size=38, max_len=38,
                name='reference2', fuzzable=True)
    session.connect(s_get('GetURCBValues'))
    # 设置非缓存报告控制块值，服务码94
def fuzzing_SetUrcBValues(session):
        s_initialize(name="SetUrcBValues")
        with s_block("APCH"):
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
            s_bytes(value=bytes([0x5e]), size=1, max_len=1, name='SC', fuzzable=False)
            s_bytes(value=bytes([0x26, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
        with s_block("ASDU"):
            s_bytes(value=bytes([0xdf, 0x01]), size=2, max_len=2, name='ReqID', fuzzable=False)
            s_bytes(value=bytes([0x01, 0x01, 0xff]), size=3, max_len=3, name='urcb', fuzzable=False)
            s_bytes(value=bytes([0xff, 0x80, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54, 0x31, 0x47
                                    , 0x5a, 0x4b, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x4c, 0x4e, 0x30, 0x2e, 0x75, 0x72,
                                 0x63, 0x62,
                                 0x41, 0x69, 0x6e, 0x30, 0x31]), size=33, max_len=33,
                    name='reference', fuzzable=True)
            s_bytes(value=bytes([0x80]), size=1, max_len=1, name='gi', fuzzable=False)
        session.connect(s_get('SetUrcBValues'))
    #读日志控制块值，服务码95
def fuzzing_GetLCBValues(session):
    s_initialize(name="GetLCBValues")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x5f]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x2f, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0xd0, 0x01]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='header', fuzzable=False)
        s_bytes(value=bytes([0x2b, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54,0x31,
                             0x47, 0x5a, 0x4b, 0x50,0x52,0x4f,0x54,0x2f,0x4c,0x4c, 0x4e,0x30,
                             0x2e, 0x64,0x73,0x54,0x72,0x69,0x70,0x49,0x6e,0x66,0x6f,0x4c,
                             0x6f,0x67,0x43,0x6f,0x6e,0x74,0x72,0x6f,0x6c]), size=44, max_len=44, name='reference', fuzzable=True)
    session.connect(s_get('GetLCBValues'))

    # 设置日志控制块值，服务码96
def fuzzing_SetLCBValues(session):
    s_initialize(name="SetLCBValues")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x60]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x25, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x95, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x80, 0x40, 0x50, 0x41, 0x43, 0x53, 0x35, 0x37, 0x31, 0x31, 0x41,
                             0x47, 0x50, 0x52, 0x4f, 0x54, 0x2f, 0x4c, 0x4c, 0x4e, 0x30, 0x2e, 0x64, 0x73,
                             0x4c, 0x6f, 0x67, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c]), size=34, max_len=34,
                name='reference', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='logena', fuzzable=False)
    session.connect(s_get('SetLCBValues'))



    #按时间查询日志.服务码97
def fuzzing_QueryLogByTime(session):
    s_initialize(name="QueryLogByTime")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x61]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x29, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x10, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0xc3, 0x20, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54,
                             0x31, 0x47, 0x5a, 0x4b, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x4c, 0x4e,
                             0x30, 0x2e, 0x4c, 0x44, 0x30]), size=27, max_len=27, name='reference', fuzzable=True)
        s_bytes(value=bytes([0x03, 0x6e, 0xe8, 0x00]), size=4, max_len=4, name='start_ms', fuzzable=False)
        s_bytes(value=bytes([0x36, 0x4e]), size=2, max_len=2, name='start_day', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x41, 0xb1, 0x11]), size=4, max_len=4, name='stop_ms', fuzzable=False)
        s_bytes(value=bytes([0x36, 0x6e]), size=2, max_len=2, name='stop_day', fuzzable=False)
    session.connect(s_get('QueryLogByTime'))

    # 按时间查询日志.服务码98
def fuzzing_QueryLogAfter(session):
    s_initialize(name="QueryLogAfter")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x62]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x23, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x62, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x88, 0x80, 0x50, 0x41, 0x43, 0x53, 0x35, 0x37, 0x31, 0x31, 0x41,
                             0x47, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x44, 0x30]), size=19, max_len=19,
                name='logReference', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='start_ms', fuzzable=False)
        s_bytes(value=bytes([0x93, 0x03]), size=2, max_len=2, name='start_day', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='entry',
                fuzzable=False)
    session.connect(s_get('QueryLogAfter'))
    # 读日志状态值，服务码99
def fuzzing_GetLogStatusValues(session):
    s_initialize(name="GetLogStatusValues")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x63]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x1d, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0xcf, 0x01]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='header', fuzzable=False)
        s_bytes(value=bytes([0x1f,  0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54,
                             0x31, 0x47, 0x5a, 0x4b, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x4c, 0x4e,
                             0x30, 0x2e, 0x4c, 0x44, 0x30]), size=26, max_len=26, name='reference', fuzzable=True)
    session.connect(s_get('GetLogStatusValues'))



    #读文件，服务码128
def fuzzing_GetFile(session):
        s_initialize(name="GetFile")
        with s_block("APCH"):
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
            s_bytes(value=bytes([0x80]), size=1, max_len=1, name='SC', fuzzable=False)
            s_bytes(value=bytes([0x3c, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
        with s_block("ASDU"):
            s_bytes(value=bytes([0xb4, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
            s_bytes(value=bytes([0x37, 0x2f, 0x43, 0x4f, 0x4d, 0x54, 0x52, 0x41, 0x44, 0x45
                                    , 0x2f, 0x50, 0x41, 0x43, 0x53, 0x35, 0x39, 0x34, 0x31, 0x54,
                                 0x31, 0x47, 0x5a, 0x4b, 0x5f, 0x52, 0x43, 0x44, 0x5f, 0x34,
                                 0x5f, 0x32, 0x30, 0x32, 0x32, 0x30, 0x32, 0x32, 0x34, 0x5f,
                                 0x31, 0x37, 0x30, 0x38, 0x30, 0x37, 0x5f, 0x32, 0x33, 0x37,
                                 0x5f, 0x73, 0x2e, 0x64, 0x65, 0x73, 0x01, 0x01]), size=58, max_len=58,
                    name='reference', fuzzable=True)
        session.connect(s_get('GetFile'))

    #列文件目录，服务码132
def fuzzing_GetFileDirectory(session):
    s_initialize(name="GetFileDirectory")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x84]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x15, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x0e, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x80, 0x09, 0x2f, 0x43, 0x4f, 0x4d, 0x54, 0x52, 0x41, 0x44,
                             0x45, 0x62, 0x0b, 0x15, 0x3a, 0x81, 0x05, 0xb8, 0x0a]), size=19, max_len=19,
                name='reference', fuzzable=True)
    session.connect(s_get('GetFileDirectory'))

    # 读远程调用接口目录，服务码110

def fuzzing_GetRpcInterfaceDirectory(session):
    s_initialize(name="GetRpcInterfaceDirectory")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x6e]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x03, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
    with s_block("ASDU"):
        s_bytes(value=bytes([0x20, 0x01]), size=2, max_len=2, name='ReqID', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1,
                name='GetRpcInterfaceDirectory', fuzzable=True)
    session.connect(s_get('GetRpcInterfaceDirectory'))

    # 测试，服务码153
def fuzzing_Test(session):
    s_initialize(name="Test")
    with s_block("APCH"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
        s_bytes(value=bytes([0x99]), size=1, max_len=1, name='SC', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='FL', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='ces', fuzzable=True)
    session.connect(s_get('Test'))

    # 关联协商，服务码154
def fuzzing_cms_AssociateNegotiate(session):
        s_initialize(name="AssociateNegotiate")
        with s_block("APCH"):
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='CC', fuzzable=False)
            s_bytes(value=bytes([0x9a]), size=1, max_len=1, name='SC', fuzzable=False)
            s_bytes(value=bytes([0X0a, 0X00]), size=2, max_len=2, name='FL', fuzzable=False)
        with s_block("ASDU"):
            s_bytes(value=bytes([0X10, 0x00]), size=2, max_len=2, name='ReqID', fuzzable=False)
            s_bytes(value=bytes([0Xff, 0Xff]), size=2, max_len=2, name='apdusize', fuzzable=False)
            s_bytes(value=bytes([0X02, 0Xff, 0xfb]), size=3, max_len=3, name='aspdusize', fuzzable=False)
            s_bytes(value=bytes([0X02, 0X02, 0x01]), size=3, max_len=3, name='protocolVersion', fuzzable=True)
        session.connect(s_get('AssociateNegotiate'))



if __name__ == "__main__":
    fuzzing_main()