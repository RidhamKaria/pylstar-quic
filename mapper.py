
from events import *
from events.Events import SendFullCHLOEvent, SendInitialCHLOEvent, ZeroRTTCHLOEvent
# s = Scapy()


def QuicInputMapper(alphabet, s):
    match alphabet:
        case "InitialCHLO":
            x = s.send(SendInitialCHLOEvent())
        case "FullCHLO":
            x = s.send(SendFullCHLOEvent())
        case "ZERO-RTT":
            x = s.send(ZeroRTTCHLOEvent())
        case default:
            pass
    return x


def QuicOutputMapper(data):
    output = ""
    if data == b"EXP":
        output = "EXP"
    # el
    elif data[0] ^ 0x0c == 0:
        output = "SHLO"
    elif data[16+10: 16+10+3] == b'REJ':
        output = "REJ"
    elif data[16+8: 16+8+3] == b'REJ':
        output = "REJ"
    else:
        output = "ERROR"
    return output