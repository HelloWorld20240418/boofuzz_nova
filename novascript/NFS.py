
host_ip = ''
host_port = 2049


def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),  nova_session_param=nova_session_param)
    fuzzing_NFS(session=session)
    session.fuzz()


#NFSPROC3_NULL客户端连接服务端时，首先尝试test，测试连通性。
def fuzzing_NFS(session):
    s_initialize(name="NULL Call")
    with s_block("Remote Procedure Call"):
        s_dword(0x38438a19, name="XID", endian=">", fuzzable=False)
        s_dword(0x00000000, name="Message Type: Call (0)", endian=">",  fuzzable=False)
        s_dword(0x00000002, name="RPC Version: 2", endian=">", fuzzable=False)
        s_dword(0x000186a3, name="Program: NFS", endian=">", fuzzable=False)
        s_dword(0x00000003, name="Program Version: 3", endian=">",  fuzzable=False)
        s_dword(0x00000000, name="Procedure: NULL (0)", endian=">", fuzzable=True)
        s_qword(0x0000000000000000, name="Credentials", endian=">", fuzzable=True)
        s_qword(0x0000000000000000, name="Verifier", endian=">", fuzzable=True)


#NFSPROC3_GETATTR客户端获取指定FH（file handle）的元数据信息
    s_initialize(name="GETATTR Call")
    with s_block("Remote Procedure Call"):
        s_dword(0x5e1d0bdc, name="XID", endian=">", fuzzable=False)
        s_dword(0x00000000, name="Message Type: Call (0)", endian=">", fuzzable=False)
        s_dword(0x00000002, name="RPC Version: 2", endian=">", fuzzable=False)
        s_dword(0x000186a3, name="Program: NFS", endian=">", fuzzable=False)
        s_dword(0x00000003, name="Program Version: 3", endian=">", fuzzable=False)
        s_dword(0x00000001, name="Procedure: GETATTR (1)", endian=">", fuzzable=False)
        with s_block("Credentials"):
            s_dword(0x00000001, name="Flavor: AUTH_UNIX (1)", endian=">", fuzzable=True)
            s_dword(0x00000034, name="Length", endian=">", fuzzable=False)
            s_dword(0x3847760b, name="Stemp", endian=">", fuzzable=False)
            with s_block("Machine Name: werrmsche"):
                s_dword(0x00000009, name="Length", endian=">", fuzzable=False)
                s_string("werrmsche", name="contents", fuzzable=False)
                s_bytes(b"\x00\x00\x00", name="fill bytes", fuzzable=False)
                s_dword(0x00000000, name="UID", endian=">", fuzzable=False)
                s_dword(0x00000001, name="GID", endian=">", fuzzable=False)
            with s_block("Auxiliary GIDs (5)"):
                s_dword(0x00000005, name="Auxiliary GID", endian=">", fuzzable=False)
                s_dword(0x00000001, name="GID1", endian=">", fuzzable=True)
                s_dword(0x00000000, name="GID2", endian=">", fuzzable=False)
                s_dword(0x00000002, name="GID3", endian=">", fuzzable=True)
                s_dword(0x00000003, name="GID4", endian=">", fuzzable=False)
                s_dword(0x00000011, name="GID5", endian=">", fuzzable=False)
        with s_block("Verifier"):
            s_dword(0x00000000, name="Flavor", endian=">", fuzzable=False)
            s_dword(0x00000000, name="Length", endian=">", fuzzable=True)
    with s_block("Network File System, GETATTR Call FH: 0x38a4e9f6"):
        with s_block("object"):
            s_dword(0x00000020, name="Length", endian=">", fuzzable=False)
            s_string(b"\x00\x10\x10\x85\x00\x00\x03\xe7\x00\x0a\x00\x00\x00\x00\xb2\x5a\x00\x00\x00\x29\x00\x0a\x00\x00\x00\x00\xb2\x5a\x00\x00\x00\x29", name="FileHandle")



    session.connect(s_get('NULL Call'))
    session.connect(s_get('GETATTR Call'))


if __name__ == "__main__":
    fuzzing_main()
