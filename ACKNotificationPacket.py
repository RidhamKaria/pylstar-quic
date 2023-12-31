from scapy.fields import *
from scapy.packet import Packet

from util.string_to_ascii import string_to_ascii


class AckNotificationPacket(Packet):
    """
    Holds the ack packet which will be send to the server.
    """
    name = "Ack Notification Packet"

    fields_desc = [
        XByteField("Public_Flags", 0x18),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        LEShortField("Packet_Number", 512),

        # Message authentication hash
        StrFixedLenField("Message_Authentication_Hash", string_to_ascii(""), 12),
    ]
