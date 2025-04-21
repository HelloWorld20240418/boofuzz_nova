host_ip = ''
host_port = 69

def fuzzing_main():

    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port),),nova_session_param=nova_session_param)
    fuzzing_Read_Request(session=session)
    fuzzing_wirte_Request(session=session)
    session.fuzz()    
    
def fuzzing_Read_Request(session):
    s_initialize("RRQ")
    s_static("\x00\x01")
    s_string("filename", name="Filename")
    s_static("\x00")
    s_group("Method", ['octet', 'mail', 'netascii'])
    s_static("\x00")
    session.connect(s_get("RRQ"))
    
def fuzzing_wirte_Request(session):
    s_initialize("WRQ")
    s_static("\x00\x02")
    s_string("filename", name="Filename")
    s_static("\x00")
    s_group("Method", ['octet', 'mail', 'netascii'])
    s_static("\x00")
    session.connect(s_get("WRQ"))
    

if __name__ == "__main__":
    fuzzing_main()