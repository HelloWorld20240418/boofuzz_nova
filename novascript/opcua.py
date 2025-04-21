
host_ip = ''
host_port = 4840

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)


    fuzzing_Hello_message(session=session)
    fuzzing_opensecurechannelrequest(session=session)
    fuzzing_UA_secure_conversation_message(session=session)
    fuzzing_ClosesecureChannel_message(session=session)
    session.fuzz()

#hello message
def fuzzing_Hello_message(session):
    s_initialize(name="Hello_message")
    with s_block("Hello_message"):
        s_bytes(value=bytes([0x48, 0x45,0x4c]), size=3, max_len=3, name='message', fuzzable=False)
        s_bytes(value=bytes([0x46]), size=1, max_len=1, name='Chunk_Type', fuzzable=True)
        s_bytes(value=bytes([0x3c, 0x00, 0x00,0x00]), size=4, max_len=4, name='Message_Size', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x00]), size=4, max_len=4, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x01, 0x00]), size=4, max_len=4, name='ReceiveBufferSize', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x01, 0x00]), size=4, max_len=4, name='sendBufferSize', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x01]), size=4, max_len=4, name='maxmessagesize', fuzzable=True)
        s_bytes(value=bytes([0x88, 0x13, 0x00, 0x00]), size=4, max_len=4, name='maxchunkcount', fuzzable=True)
        s_bytes(value=bytes([0x1c, 0x00, 0x00, 0x00]), size=4, max_len=4, name='maxchunkcount_harder', fuzzable=False)
        s_bytes(value=bytes([0x6f, 0x70, 0x63, 0x2e,0x74,0x63,0x70,0x3a,0x2f,0x2f,0x31,0x39,0x32,0x2e,0x31,
                             0x36,0x38,0x2e,0x31,0x2e,0x31,0x38,0x37,0x3a,0x34,0x38,0x34,0x30]), size=28, max_len=28, name='EdnpointUrl', fuzzable=True)
    session.connect(s_get('Hello_message'))


#opensecurechannel_request
def fuzzing_opensecurechannelrequest(session):
    s_initialize(name="opensecurechannelrequest")
    with s_block("opensecurechannelrequest"):
        s_bytes(value=bytes([0x4f, 0x50, 0x4e]), size=3, max_len=3, name='message', fuzzable=False)
        s_bytes(value=bytes([0x46]), size=1, max_len=1, name='Chunk_Type', fuzzable=True)
        s_bytes(value=bytes([0x85, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Message_Size', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='sECURECHANNE1id', fuzzable=True)
        s_bytes(value=bytes([0x2f, 0x00, 0x00, 0x00]), size=4, max_len=4, name='securechanneiid_harder', fuzzable=False)
        s_bytes(value=bytes([0x68, 0x74, 0x74, 0x70,0x3a,0x2f,0x2f,0x6f,0x70,0x63,0x66,0x6f,0x75,0x6e,0x64,0x61,0x74,
                             0x69,0x6f,0x6e,0x2e,0x6f,0x72,0x67,0x2f,0x55,0x41,0x2f,0x53,0x65,0x63,0x75,0x72,0x69,0x74,0x79,
                             0x50,0x6f,0x6c,0x69,0x63,0x79,0x23,0x4e,0x6f,0x6e,0x65]), size=47, max_len=47, name='Securitypolocyuil', fuzzable=True)
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff]), size=4, max_len=4, name='Sendercertificate', fuzzable=True)
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff]), size=4, max_len=4, name='Receivercertificatethumbprint', fuzzable=True)
        s_bytes(value=bytes([0x33, 0x00, 0x00, 0x00]), size=4, max_len=4, name='sequencenumber', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00, 0x00, 0x00]), size=4, max_len=4, name='requestid', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='nodeid_encodingmask', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='nodeid_namespace_index', fuzzable=True)
        s_bytes(value=bytes([0xbe,0x01]), size=2, max_len=2, name='nodeid_identifier_numeric', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='encodingmask', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='identifier_numeric', fuzzable=True)
        s_bytes(value=bytes([0x13,0x3f,0xc3,0xd0,0x4e,0x66,0xd6,0x01]), size=8, max_len=8, name='timestamp', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='requesthandle', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='return_diagnostics', fuzzable=True)
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff]), size=4, max_len=4, name='auditEntryID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='timeouthint', fuzzable=True)
        s_bytes(value=bytes([ 0x00, 0x00, 0x00]), size=3, max_len=3, name='additionalheader', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='clientprotocolversion', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='securitytokenrequesttype', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Messagesecuritymode', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Messagesecuritymode_harder', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Clientnonce', fuzzable=True)
        s_bytes(value=bytes([0xe0,0x93,0x04,0x00]), size=4, max_len=4, name='requestedlifetime', fuzzable=True)
    session.connect(s_get('opensecurechannelrequest'))

def fuzzing_UA_secure_conversation_message(session):

#UA_secure_conversation_message
    s_initialize(name="UA_secure_conversation_message")
    with s_block("UA_secure_conversation_message"):
        s_bytes(value=bytes([0x4d, 0x53, 0x47]), size=3, max_len=3, name='message_type', fuzzable=False)
        s_bytes(value=bytes([0x46]), size=1, max_len=1, name='Chunk_Type', fuzzable=False)
        s_bytes(value=bytes([0x61, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Message_Size', fuzzable=False)
        s_bytes(value=bytes([0x92, 0x85, 0x96, 0x00]), size=4, max_len=4, name='sECURECHANNE1id', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Security_token_id', fuzzable=False)
        s_bytes(value=bytes([0x34, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Security_sequence_nuber', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Security_requestid', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Nodeid_ENcodingmask', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Nodeid_Namespace_index', fuzzable=False)
        s_bytes(value=bytes([0xac,0x01]), size=2, max_len=2, name='Nodeid_Identifier_numeric', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='encodingmask', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='identifier_numeric', fuzzable=True)
        s_bytes(value=bytes([0x13, 0x3f, 0xc3, 0xd0, 0x4e, 0x66, 0xd6, 0x01]), size=8, max_len=8, name='timestamp',
                fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00, 0x00, 0x00]), size=4, max_len=4, name='requesthandle', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='return_diagnostics', fuzzable=True)
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff]), size=4, max_len=4, name='auditEntryID', fuzzable=True)
        s_bytes(value=bytes([0x10, 0x27, 0x00, 0x00]), size=4, max_len=4, name='timeouthint', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='additionalheader', fuzzable=False)
        s_bytes(value=bytes([0x1c, 0x00, 0x00,0x00]), size=4, max_len=4, name='additionalheader——hander', fuzzable=False)
        s_bytes(value=bytes([0x6f,0x70,0x63,0x2e,0x74,0x63,0x70,0x3a,0x2f,0x2f,0x31,0x39,0x32,0x2e,0x31,
                             0x31,0x36,0x38,0x2e,0x31,0x2e,0x31,0x38,0x37,0x3a,0x34,0x38,0x34,0x30]),size=28,max_len=28,name="endpointurl",fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='Arraysize', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00,0x00]), size=4, max_len=4, name='Arraysize1', fuzzable=False)
    session.connect(s_get('UA_secure_conversation_message'))


        #ClosesecureChannel_message
def fuzzing_ClosesecureChannel_message(session):
    s_initialize(name="ClosesecureChannel_message")
    with s_block("ClosesecureChannel_message"):
        s_bytes(value=bytes([0x43, 0x4c, 0x4f]), size=3, max_len=3, name='message_type', fuzzable=False)
        s_bytes(value=bytes([0x46]), size=1, max_len=1, name='Chunk_Type', fuzzable=True)
        s_bytes(value=bytes([0x39, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Message_Size', fuzzable=False)
        s_bytes(value=bytes([0x92, 0x85, 0x96, 0x00]), size=4, max_len=4, name='sECURECHANNE1id', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Security_token_id', fuzzable=False)
        s_bytes(value=bytes([0x35, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Security_sequence_nuber',
                fuzzable=False)
        s_bytes(value=bytes([0x03, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Security_requestid', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Nodeid_ENcodingmask', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Nodeid_Namespace_index', fuzzable=False)
        s_bytes(value=bytes([0xc4, 0x01]), size=2, max_len=2, name='Nodeid_Identifier_numeric', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='encodingmask', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='identifier_numeric', fuzzable=True)
        s_bytes(value=bytes([0xe3, 0x8c, 0xc3, 0xd0, 0x4e, 0x66, 0xd6, 0x01]), size=8, max_len=8, name='timestamp',
            fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='requesthandle', fuzzable=True)
    s_bytes(value=bytes([0x01, 0x00, 0x00, 0x00]), size=4, max_len=4, name='requesthandle', fuzzable=True)
    s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='return_diagnostics', fuzzable=True)
    s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff]), size=4, max_len=4, name='auditEntryID', fuzzable=True)
    s_bytes(value=bytes([0x10, 0x27, 0x00, 0x00]), size=4, max_len=4, name='timeouthint', fuzzable=True)
    s_bytes(value=bytes([0x00]), size=1, max_len=1, name='encodingmask1', fuzzable=True)
    s_bytes(value=bytes([0x00]), size=1, max_len=1, name='identifier_numeric1', fuzzable=True)
    s_bytes(value=bytes([0x00]), size=1, max_len=1, name='has_binary_body', fuzzable=True)


    session.connect(s_get('ClosesecureChannel_message'))




if __name__ == "__main__":
    fuzzing_main()
