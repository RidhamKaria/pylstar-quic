from scapy.fields import *
from scapy.packet import Packet

from util.SessionInstance import SessionInstance
from util.string_to_ascii import string_to_ascii


class FullCHLOPacket(Packet):
    """
    Full client hello packet
    Taken from Wireshark Capture example-local-clemente-aesgcm
    """
    name = "FullCHLO"

    fields_desc = [
        XByteField("Public_Flags", 0x08),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        # StrFixedLenField("Version", "Q043", 4),
        StrFixedLenField("Packet_Number", 1, 1), # LEShortField
        # ByteField("Packet_Number", 1), # LEShortField

        # Message Authentication Hash, 12 bytes
        StrFixedLenField("Message_Authentication_Hash", string_to_ascii("5f67187558566e93f02ce5d0"), 12),

        
        XByteField("Frame_Type", 0xa4),  # Stream
        ByteField("Stream_ID", 1),

        LEShortField("Offset", 0x0004),  # there in the source
        LEShortField("Data_Length", 0x0004), #LEIntField
        StrFixedLenField("Tag1", "CHLO", 4),
        LEShortField("Tag_Number", 23),
        ShortField("Padding", 0),

        # List of tags

        StrFixedLenField("PAD", "PAD", 3),
        ByteField("Xtra_1", 0),
        LEIntField("tag_offset_end_1", 519),
        
        StrFixedLenField("SNI", "SNI", 3), #9
        ByteField("Xtra_2", 0),
        LEIntField("tag_offset_end_2", 540),
        
        StrFixedLenField("STK", "STK", 3), # 60
        ByteField("Xtra_3", 0),
        LEIntField("tag_offset_end_3", 600), #

        StrFixedLenField("SNO", "SNO", 3), # 56
        ByteField("Xtra_4", 0),
        LEIntField("tag_offset_end_4", 656),

        StrFixedLenField("VER", "VER", 3), # 4
        ByteField("Xtra_5", 0),
        LEIntField("tag_offset_end_5", 660),

        StrFixedLenField("CCS", "CCS", 3), # 16
        ByteField("Xtra_6", 0),
        LEIntField("tag_offset_end_6", 676),

        StrFixedLenField("NONC", "NONC", 4), # 32
        LEIntField("tag_offset_end_7", 708),

        StrFixedLenField("AEAD", "AEAD", 4), #4
        LEIntField("tag_offset_end_8", 712),
        
        StrFixedLenField("UAID", "UAID", 4), #12
        #ByteField("Xtra_6", 0),
        LEIntField("tag_offset_end_9", 724),

        StrFixedLenField("SCID", "SCID", 4), # 16
        LEIntField("tag_offset_end_10", 740),
        
        StrFixedLenField("TCID", "TCID", 4), #4
        #ByteField("Xtra_9", 0),
        LEIntField("tag_offset_end_11", 744),

        StrFixedLenField("PDMD", "PDMD", 4),
        LEIntField("tag_offset_end_12", 748),

        StrFixedLenField("SMHL", "SMHL", 4),  # 4
        #ByteField("Xtra_11", 0),
        LEIntField("tag_offset_end_13", 752),
        
        StrFixedLenField("ICSL", "ICSL", 4), # 4
        LEIntField("tag_offset_end_14", 756),

        StrFixedLenField("PUBS", "PUBS", 4), # 32
        LEIntField("tag_offset_end_15", 788),

        StrFixedLenField("MIDS", "MIDS", 4), # 4
        LEIntField("tag_offset_end_16", 792),

        StrFixedLenField("SCLS", "SCLS", 4),  # 4
        #ByteField("Xtra_14", 0),
        LEIntField("tag_offset_end_17", 796), 

        StrFixedLenField("KEXS", "KEXS", 4),  # 4
        LEIntField("tag_offset_end_18", 800),

        StrFixedLenField("XLCT", "XLCT", 4), # 16
        LEIntField("tag_offset_end_19", 808),

        StrFixedLenField("CSCT", "CSCT", 4), # 0
        #ByteField("Xtra_16", 0),
        LEIntField("tag_offset_end_20", 808),

        StrFixedLenField("CCRT", "CCRT", 4), # 8
        #ByteField("Xtra_16", 0),
        LEIntField("tag_offset_end_21", 824),

        StrFixedLenField("CFCW", "CFCW", 4), # 4
        LEIntField("tag_offset_end_22", 828),

        StrFixedLenField("SFCW", "SFCW", 4), # 4
        LEIntField("tag_offset_end_23", 832),

        StrFixedLenField("Padding_value", string_to_ascii("2d"*519), 519),
        # XByteField("Padding0", 0x2d),

        StrFixedLenField("Server_Name_Indication", "www.litespeedtech.com", 21),
        StrFixedLenField("Source_Address_Token", string_to_ascii("f7214fe6649467547b2c4e006d97c716097d05ac737b34f426404fd965e2290677fecb437701364808ec4af796bacea645afd897525ef16f"), 60),
        StrFixedLenField("SNO_Value", string_to_ascii("e4d458e2594b930f6d4f77711215adf9ebe99096c479dbf765f41d28646c4b87a0ec735e63cc4f19b9207d369e36968b2b2071ed"), 56),
        LEIntField("Version_Value", 0x33343051),
        StrFixedLenField("CCS_Value", string_to_ascii("01e8816092921ae87eed8086a2158291"), 16),
        StrFixedLenField("NONC_Value", string_to_ascii("5ac349e90091b5556f1a3c52eb57f92c12640e876e26ab2601c02b2a32f54830"), 32),
        StrFixedLenField("AEAD_Value", "AESG", 4),
        StrFixedLenField("UAID_Value", "lsquic/4.0.1", 12),
        
        # Set the server config id to the value received in the REJ packet.
        StrFixedLenField("SCID_Value", "", 16),
        LEIntField("TCID_Value", 0x00000000),
        StrFixedLenField("PDMD_Value", "X509", 4),
        LEIntField("SMHL_Value", 0x00000001),
        LEIntField("ICSL_Value", 30),
        StrFixedLenField("PUBS_Value", string_to_ascii("1403c2f3138a820f8114f282c4837d585bd00782f4ec0e5f1d39c06c49cc8043"), 32),
        LEIntField("MIDS_Value", 0x00000064),

        LEIntField("SCLS_Value", 1),
        StrFixedLenField("KEXS_Value", "C255", 4),
        StrFixedLenField("XLCT_Value", string_to_ascii("4152d1eb7d0fda23"), 8),
        StrFixedLenField("CCRT_Value", string_to_ascii("4152d1eb7d0fda23cb8b5260c0ebbd92"), 16),
        
        # need to fill some CCID value, maybe from the REJ packet, do it in the scapy_demo.py file
        LEIntField("CFCW_Value", 0x00f00000),
        LEIntField("SFCW_Value", 0x00600000),

# Additional frame: PADDING (0x00)
        StrFixedLenField("Padding_Value", string_to_ascii("00"*318), 318),
        #XByteField("Padding832", 0x00), 
        # maybe needed, calculate later
        
    ]