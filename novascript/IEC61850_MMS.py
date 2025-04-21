host_ip = ''
host_port = 102

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_COTP(session=session)
    fuzzing_initiate_RequestPDU(session=session)
    session.fuzz()


def fuzzing_COTP(session):
    s_initialize(name="COTP")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x16]), size=2, max_len=2, name='Length', fuzzable=False)
    with s_block("ISO 8073/X.224 COTP"):
        s_bytes(value=bytes([0x11]),size=1,max_len=1,name='length',fuzzable=False)
        s_bytes(value=bytes([0xe0]), size=1, max_len=1, name='PDU Type', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Destination', fuzzable=False)
        s_bytes(value=bytes([0xb0, 0x01]), size=2, max_len=2, name='Source_reference', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Class', fuzzable=False)
        s_bytes(value=bytes([0xc0]), size=1, max_len=1, name='Parameter_code', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Parameter_length', fuzzable=False)
        s_bytes(value=bytes([0x0a]), size=1, max_len=1, name='TPDU_size', fuzzable=False)
        s_bytes(value=bytes([0xc1]), size=1, max_len=1, name='Parameter_code_2', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Parameter_length_2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Source_TSAP', fuzzable=False)
        s_bytes(value=bytes([0xc2]), size=1, max_len=1, name='Parameter_code_3', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Parameter_length_3', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x02]), size=2, max_len=2, name='Source_TSAP_2', fuzzable=False)
        session.connect(s_get('COTP'))

def fuzzing_initiate_RequestPDU(session):
    s_initialize(name="initiate_RequestPDU")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x00,0xc5]), size=2, max_len=2, name='Length', fuzzable=False)
    with s_block("ISO_8073_x.224"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Length', fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name='PDU_type', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='TPDU', fuzzable=False)
    with s_block("ISO_8027_1"):
        s_bytes(value=bytes([0x0d]), size=1, max_len=1, name='SPDU_type', fuzzable=False)
        s_bytes(value=bytes([0xbc]), size=1, max_len=1, name='length7', fuzzable=False)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='Parameter_type', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='Parameter_length', fuzzable=False)
        s_bytes(value=bytes([0x13]), size=1, max_len=1, name='Parameter_type1', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Parameter_length1', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Flags1', fuzzable=False)
        s_bytes(value=bytes([0x16]), size=1, max_len=1, name='Parameter_type2', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Parameter_length2', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Flags2', fuzzable=False)
        s_bytes(value=bytes([0x14]), size=1, max_len=1, name='Parameter_type3', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Parameter_length3', fuzzable=False)
        s_bytes(value=bytes([0x00,0x02]), size=2, max_len=2, name='Flags3', fuzzable=False)
        s_bytes(value=bytes([0x33]), size=1, max_len=1, name='Parameter_type4', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Parameter_length4', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Callong_session_selector', fuzzable=False)
        s_bytes(value=bytes([0x34]), size=1, max_len=1, name='Parameter_type5', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Parameter_length5', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x02]), size=2, max_len=2, name='Callong_session_selector1', fuzzable=False)
        s_bytes(value=bytes([0xc1]), size=1, max_len=1, name='Parameter_type6', fuzzable=False)
        s_bytes(value=bytes([0xa6]), size=1, max_len=1, name='Parameter_length6', fuzzable=False)
    with s_block("ISO_8023"):
        s_bytes(value=bytes([0x31,0x81,0xa3,0xa0,0x03,0x80,0x01]), size=7, max_len=7, name='CP_type', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='mode_value', fuzzable=False)
        s_bytes(value=bytes([0xa2,0x81,0x9b]), size=3, max_len=3, name='normal-mode-paramete_hard', fuzzable=False)
        s_bytes(value=bytes([0x80,0x02]), size=2, max_len=2, name='padding_hard', fuzzable=False)
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name='padding', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='protocol_version', fuzzable=False)
        s_bytes(value=bytes([0x81,0x04,0x00,0x00,0x00,0x01]), size=6, max_len=6, name='calling_presentation_selector', fuzzable=False)
        s_bytes(value=bytes([0x82, 0x04]), size=2, max_len=2, name='hard1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x02]), size=4, max_len=4, name='calling_presentation_selector1',fuzzable=False)
        s_bytes(value=bytes([0xa4, 0x23]), size=2, max_len=2, name='hard2', fuzzable=False)
        s_bytes(value=bytes([0x30,0x0f,0x02,0x01]), size=4, max_len=4, name='hard3', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='presentation_context_identifier', fuzzable=False)
        s_bytes(value=bytes([0x06,0x04]), size=2, max_len=2, name='hard4', fuzzable=False)
        s_bytes(value=bytes([0x52, 0x01, 0x00, 0x01]), size=4, max_len=4, name='abstract_syntax_name', fuzzable=False)
        s_bytes(value=bytes([0x30, 0x04,0x06,0x02]), size=4, max_len=4, name='hard5', fuzzable=False)
        s_bytes(value=bytes([0x51, 0x01]), size=2, max_len=2, name='Transfer_syntax_name', fuzzable=False)
        s_bytes(value=bytes([0x30, 0x10, 0x02, 0x01]), size=4, max_len=4, name='hard6', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='presentation_context_identifier1', fuzzable=False)
        s_bytes(value=bytes([0x06, 0x05]), size=2, max_len=2, name='hard7', fuzzable=False)
        s_bytes(value=bytes([0x28, 0xca, 0x22, 0x02,0x01]), size=5, max_len=5, name='abstract_syntax_name1', fuzzable=False)
        s_bytes(value=bytes([0x30,0x04,0x06, 0x02]), size=4, max_len=4, name='hard8', fuzzable=False)
        s_bytes(value=bytes([0x51,0x01]), size=2, max_len=2, name='Transfer_syntax_name1', fuzzable=False)
        s_bytes(value=bytes([0x88,0x02]), size=2, max_len=2, name='hard9', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='Transfer_syntax_name_padding', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='presentation_context_identifier3', fuzzable=False)
        s_bytes(value=bytes([0x61, 0x60,0x30,0x5e,0x02,0x01]), size=6, max_len=6, name='hard11', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='padding1', fuzzable=False)
    with s_block("ISO-8650-1 OSI"):
        s_bytes(value=bytes([0xa0, 0x59,0x60,0x57,0x80,0x02]), size=6, max_len=6, name='hard21', fuzzable=True)
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name='padding_7', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='pprotocol_version', fuzzable=False)
        s_bytes(value=bytes([0xa1,0x07,0x06,0x05]), size=4, max_len=4, name='aSO_hard', fuzzable=False)
        s_bytes(value=bytes([0x28, 0xca, 0x22, 0x01,0x01]), size=5, max_len=5, name='aSO_context_name', fuzzable=True)
        s_bytes(value=bytes([0xa2, 0x04]), size=2, max_len=2, name='hard13', fuzzable=False)
        s_bytes(value=bytes([0x06,0x02,0x29,0x02]), size=4, max_len=4, name='ap_title_form2', fuzzable=False)
        s_bytes(value=bytes([0xa3, 0x03]), size=2, max_len=2, name='hard14', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01,0x02]), size=3, max_len=3, name='aso_qualifier_form2', fuzzable=True)
        s_bytes(value=bytes([0xa6, 0x04]), size=2, max_len=2, name='hard15', fuzzable=False)
        s_bytes(value=bytes([0x06,0x02, 0x29, 0x01]), size=4, max_len=4, name='aso_qualifier_form21', fuzzable=False)
        s_bytes(value=bytes([0xa7, 0x03]), size=2, max_len=2, name='hard16', fuzzable=False)
        s_bytes(value=bytes([ 0x02, 0x01, 0x01]), size=3, max_len=3, name='aso_qualifier_form22', fuzzable=False)
        s_bytes(value=bytes([0xbe, 0x32, 0x28, 0x30]), size=4, max_len=4, name='hard17', fuzzable=False)
        s_bytes(value=bytes([0x06, 0x02, 0x51, 0x01]), size=4, max_len=4, name='direct_reference', fuzzable=False)
        s_bytes(value=bytes([0x02,0x01,0x03]), size=3, max_len=3, name='indirect_reference', fuzzable=False)
        s_bytes(value=bytes([0xa0, 0x27]), size=2, max_len=2, name='indirect_reference_hard16', fuzzable=False)
    with s_block("MMS"):
        s_bytes(value=bytes([0xa8,0x25,0x80, 0x02]), size=4, max_len=4, name='hard18', fuzzable=False)
        s_bytes(value=bytes([0x7d, 0x00]), size=2, max_len=2, name='localDetailCalling', fuzzable=False)
        s_bytes(value=bytes([0x81, 0x01, 0x14]), size=3, max_len=3, name='proposedMaxServOutstandingCalling', fuzzable=True)
        s_bytes(value=bytes([0x82, 0x01, 0x14]), size=3, max_len=3, name='proposedMaxServOutstandingCalled',fuzzable=False)
        s_bytes(value=bytes([0x83, 0x01, 0x04]), size=3, max_len=3, name='proposedDataStructureNestingLevel',fuzzable=False)
        s_bytes(value=bytes([0xa4, 0x16]), size=2, max_len=2, name='hard19', fuzzable=False)
        s_bytes(value=bytes([0x80, 0x01, 0x01]), size=3, max_len=3, name='proposedVersionNumber',fuzzable=False)
        s_bytes(value=bytes([0x81, 0x03, 0x05]), size=3, max_len=3, name='padding2',fuzzable=False)
        s_bytes(value=bytes([0xfb, 0x00]), size=2, max_len=2, name='proposeParameterCBB', fuzzable=False)
        s_bytes(value=bytes([0x82, 0x0c, 0x03]), size=3, max_len=3, name='padding3', fuzzable=False)
        s_bytes(value=bytes([0x6e, 0x1d, 0x00,0x00,0x00,0x00,0x00,0x64,0x00,0x01,0x98]), size=11, max_len=11, name='serviceSupportedCalling', fuzzable=True)
    session.connect(s_get('COTP'),s_get('initiate_RequestPDU'))











if __name__ == "__main__":
    fuzzing_main()
