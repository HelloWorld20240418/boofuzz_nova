

host_ip = ''
host_port = 80

def main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)


    # 定义基础HTTP请求结构
    def http_request_template(name, path):
        s_initialize(name=name)
        with s_block("Request-Line"):
            s_static("GET ")
            s_string(path, name="request_path", fuzzable=False)  # 路径单独定义
            s_static(" HTTP/1.1\r\n")

        with s_block("Headers"):
            s_static("Host: ")
            s_string(host_ip, name="host_header", fuzzable=True)
            s_static("\r\nUser-Agent: Boofuzz HLS Fuzzer\r\n")
            s_static("Accept: */*\r\n\r\n")

    # -------------------- 主播放列表请求 --------------------
    http_request_template(name="MasterPlaylist", path="/live/master.m3u8")
    s_get("MasterPlaylist").original_value = (
        b"GET /live/master.m3u8?version="
        b"{fuzz}"  # 模糊查询参数
        b" HTTP/1.1\r\n"
        b"Host: {fuzz}\r\n"
        b"User-Agent: Boofuzz HLS Fuzzer\r\n"
        b"Accept: */*\r\n\r\n"
    )

    # -------------------- 媒体播放列表请求 --------------------
    http_request_template(name="MediaPlaylist", path="/videos/media_")
    with s_block("MediaPlaylistParams"):
        s_string("low", name="bitrate", fuzzable=True)  # 比特率标识符
        s_static(".m3u8?seq=")
        s_delim("=", fuzzable=False)
        s_random(min_length=0, max_length=0xFFFFFFFF, name="sequence", fuzzable=True)
        s_static("&chunk=")
        s_string("00001", name="chunk_id", fuzzable=True)

    # -------------------- TS分片请求模糊化 --------------------
    http_request_template(name="TS_Chunk", path="/segments/")
    with s_block("ChunkPath"):
        s_string("chunk", name="chunk_prefix", fuzzable=True)
        s_delim("_", fuzzable=False)
        s_random(min_length=0, max_length=0xFFFF, name="segment_num", fuzzable=True)
        s_static(".ts")

 

    # 配置测试顺序和覆盖率
    session.connect(s_get("MasterPlaylist"))
    session.connect(s_get("MasterPlaylist"), s_get("MediaPlaylist"))
    session.connect(s_get("MediaPlaylist"), s_get("TS_Chunk"))
    #session.connect(s_get("MasterPlaylist"), s_get("EncryptionKey"))

    # 启动模糊测试
    session.fuzz()


if __name__ == "__main__":
    main()
