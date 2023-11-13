from scapy.fields import *
from scapy.packet import Packet

from XStrFixedLenField import XStrFixedLenField
from util.string_to_ascii import string_to_ascii


class QUICHeader(Packet):
    """
    The header for the QUIC CHLO packet
    Taken from Wireshark capture example-local-clemente-aesgcm
    """
    name = "QUIC"
    fields_desc = [
        XByteField("Public_Flags", 0x09),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        StrFixedLenField("Version", "Q043", 4),
        StrFixedLenField("Packet_Number", 1, 1), # LEShortField
        # ByteField("Packet_Number", 1), # LEShortField

        # Message Authentication Hash, 12 bytes
        StrFixedLenField("Message_Authentication_Hash", string_to_ascii("5f67187558566e93f02ce5d0"), 12),

        XByteField("Frame_Type", 0xa0),  # Stream
        ByteField("Stream_ID", 1),

        LEShortField("Data_Length", 0x0004), #LEIntField
        StrFixedLenField("Tag1", "CHLO", 4),
        LEShortField("Tag_Number", 18),

        ShortField("Padding", 0),

        StrFixedLenField("PAD", "PAD", 3),
        ByteField("Xtra_1", 0),
        LEIntField("tag_offset_end_1", 779),
        
        StrFixedLenField("SNI", "SNI", 3), #9
        ByteField("Xtra_2", 0),
        LEIntField("tag_offset_end_2", 800),
        
        StrFixedLenField("STK", "STK", 3), #0
        ByteField("Xtra_3", 0),
        LEIntField("tag_offset_end_3", 800), #0

        StrFixedLenField("SNO", "SNO", 3), #0
        ByteField("Xtra_4", 0),
        LEIntField("tag_offset_end_4", 800),
        
        StrFixedLenField("VER", "VER", 3), #4
        ByteField("Xtra_5", 0),
        LEIntField("tag_offset_end_5", 804),
        
        StrFixedLenField("CCS", "CCS", 3), #16
        ByteField("Xtra_6", 0),
        LEIntField("tag_offset_end_6", 820),

        # StrFixedLenField("MSPC", "MSPC", 4),
        # ByteField("Xtra 5", 0),
        # LEIntField("tag_offset_end_5", 1104),

        StrFixedLenField("AEAD", "AEAD", 4), #4
        LEIntField("tag_offset_end_7", 824),

        StrFixedLenField("UAID", "UAID", 4), #12
        #ByteField("Xtra_6", 0),
        LEIntField("tag_offset_end_8", 836),

        StrFixedLenField("TCID", "TCID", 4), #4
        #ByteField("Xtra_9", 0),
        LEIntField("tag_offset_end_9", 840),
        
        StrFixedLenField("PDMD", "PDMD", 4), #4
        # ByteField("Xtra_10", 0),
        LEIntField("tag_offset_end_10", 844),

        StrFixedLenField("SMHL", "SMHL", 4),  # 4
        #ByteField("Xtra_11", 0),
        LEIntField("tag_offset_end_11", 848),

        StrFixedLenField("ICSL", "ICSL", 4), #4
        # ByteField("Xtra_12", 0),
        LEIntField("tag_offset_end_12", 852),

        # StrFixedLenField("CTIM", "CTIM", 4),
        # ByteField("Xtra 9", 0),
        # LEIntField("tag_offset_end_9", 1124),

        # StrFixedLenField("NONP", "NONP", 4),
        # ByteField("Xtra 10", 0),
        # LEIntField("tag_offset_end_10", 1156),
        
        StrFixedLenField("MIDS", "MIDS", 4), #4
        # ByteField("Xtra_13", 0),
        LEIntField("tag_offset_end_13", 856),
        
        StrFixedLenField("SCLS", "SCLS", 4),  # 4
        #ByteField("Xtra_14", 0),
        LEIntField("tag_offset_end_15", 860),

        StrFixedLenField("KEXS", "KEXS", 4),  #4
        LEIntField("tag_offset_end_14", 864),
        
        StrFixedLenField("CSCT", "CSCT", 4), #0
        #ByteField("Xtra_16", 0),
        LEIntField("tag_offset_end_16", 864),
        
        StrFixedLenField("CFCW", "CFCW", 4), #4
        #ByteField("Xtra_17", 0),
        LEIntField("tag_offset_end_17", 868),
        
        StrFixedLenField("SFCW", "SFCW", 4), #4
        # ByteField("Xtra_18", 0),
        LEIntField("tag_offset_end_18", 872),

        # Now have 905 times the value 2d
        StrFixedLenField("Padding_value", string_to_ascii("-"*779), 779),
        #XByteField("Padding0", 0x00),

        StrFixedLenField("Server_Name_Indication", "www.litespeedtech.com", 21),
        LEIntField("Version_Value", 0x33343051), # 0x51303433 0x33343051  Q043 = 0x33343051, Q039 = 0x3633051

        #LEIntField("AEAD_Value", 0x41455347), # 0x47534541

        # Common Certificate Sets
        StrFixedLenField("CCS_Value", string_to_ascii("01e8816092921ae87eed8086a2158291"), 16),

        StrFixedLenField("AEAD_Value", "AESG", 4),
        StrFixedLenField("UAID_Value", "lsquic/4.0.1", 12),
        LEIntField("TCID_Value", 0x00000000),
        StrFixedLenField("PDMD_Value", "X509", 4),
        LEIntField("SMHL_Value", 0x00000001),
        LEIntField("ICSL_Value", 30),

        LEIntField("MIDS_Value", 0x00000064),
        LEIntField("SCLS_Value", 1),
        StrFixedLenField("KEXS_Value", "C255", 4),
        LEIntField("CFCW_Value", 0x00f00000),
        LEIntField("SFCW_Value", 0x00600000),

        StrFixedLenField("Padding_Value", string_to_ascii("00"*316), 316),

        # XByteField("Padding873", 0x00),



    ]