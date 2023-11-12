import datetime
import time, os
import json
import random
from collections import Counter
from statistics import median, mean
from Crypto.Cipher import AES

from peewee import OperationalError
from scapy import route # DO NOT REMOVE!!
from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.all import Raw, bytes_hex
from scapy.sendrecv import send, sr
from scapy.supersocket import L3RawSocket

from ACKNotificationPacket import AckNotificationPacket
from ACKPacket import ACKPacket
from AEADPacketDynamic import AEADPacketDynamic, AEADFieldNames
from AEADRequestPacket import AEADRequestPacket
from DynamicCHLOPacket import DynamicCHLOPacket
from FramesProcessor import FramesProcessor
from FullCHLOPacket import FullCHLOPacket
from FullCHLOPacketNoPadding import FullCHLOPacketNoPadding
from PacketNumberInstance import PacketNumberInstance
from PingPacket import PingPacket
from QUIC_43_localhost import QUICHeader
from RejectionPacket import RejectionPacket
from SecondACKPacket import SecondACKPacket
from caching.CacheInstance import CacheInstance
from caching.SessionModel import SessionModel
from connection.ConnectionInstance import ConnectionEndpoint, CryptoConnectionManager
from crypto.CryptoManager import CryptoManager
from crypto.dhke import dhke
from crypto.fnv128a import FNV128A
from events.Events import SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent, SendFullCHLOEvent, \
    ZeroRTTCHLOEvent, ResetEvent
from sniffer.sniffer import Sniffer
from util.NonDeterminismCatcher import NonDeterminismCatcher
from util.RespondDummy import RespondDummy
from util.SessionInstance import SessionInstance
from util.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
from util.split_at_every_n import split_at_nth_char
from util.string_to_ascii import string_to_ascii_old, string_to_ascii
import time
import logging
import os


# header lenght: 22 bytes
DPORT=443

class Scapy:

    TIMEOUT = 0.3263230323791504 * 5
    server_adress_token = b''
    server_nonce = b''
    server_connection_id = b''


    def __init__(self) -> None:
        currenttime = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
        filename = 'log_{}.txt'.format(currenttime)
        #logging.basicConfig(filename=filename, level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
        self.logger = logging.getLogger(__name__)

        dhke.set_up_my_keys()

    def reset(self, reset_server, reset_run=True):
        # also reset the server
        if reset_server:
            # remove the previous session
            CacheInstance.get_instance().remove_session_model()
            filename = str(time.time())
            open('resets/{}'.format(filename), 'a')
            time.sleep(8)

        if reset_run:
            # For the three times a command we do not want to remove the run events, only when there is a complete reset
            # which occurs after an iteration or after an explicit RESET command.

            self.run = ""
            # PacketNumberInstance.get_instance().reset()
            conn_id = random.getrandbits(64)
            SessionInstance.get_instance().shlo_received = False
            SessionInstance.get_instance().scfg = ""
            SessionInstance.get_instance().zero_rtt = False
            self.logger.info("Changing CID from {}".format(SessionInstance.get_instance().connection_id))
            SessionInstance.get_instance().connection_id_as_number = conn_id
            SessionInstance.get_instance().connection_id = str(format(conn_id, 'x').zfill(16))  # Pad to 16 chars
            self.logger.info("To {}".format(SessionInstance.get_instance().connection_id))

    def send_chlo(self, only_reset):
        self.reset(only_reset)

        chlo = QUICHeader()
        conf.L3socket = L3RawSocket

        chlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))

        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        chlo.setfieldval("Packet_Number", string_to_ascii(str("%02x" % packet_number)))

        associated_data = extract_from_packet(chlo, end=14)
        body = extract_from_packet(chlo, start=26)

        message_authentication_hash = FNV128A().generate_hash(associated_data, body)
        # print(message_authentication_hash)
        chlo.setfieldval('Message_Authentication_Hash', string_to_ascii(message_authentication_hash))
        
        # mac_val = b'\xf3\x3e\x04\xda\x45\xca\x71\x9c\x49\x9c\xf6\x58'
        # chlo.setfieldval('Message_Authentication_Hash', mac_val)

        # Store chlo for the key derivation
        # SessionInstance.get_instance().chlo = extract_from_packet_as_bytestring(chlo, start=30, end=1054)

        # self.sniffer.add_observer(self)


        p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=DPORT, sport=61250) / chlo
        ans, unans = sr(p,timeout=self.TIMEOUT)

        packet = bytes(ans[0][1][UDP][Raw])
        packet_type = packet[16+10: 16+10+3]
        if packet_type ==b'REJ':
            self.server_adress_token = packet[16*5+10: 16*5+10+60]
            self.server_connection_id = packet[16*35+2: 16*35+2+16]
            self.server_nonce = packet[16*9+6: 16*9+6+56]
            SessionInstance.get_instance().server_nonce = self.server_nonce.hex()
            SessionInstance.get_instance().scfg = packet[16*28+14: 16*28+14+175].hex()
            # SessionInstance.get_instance().cert = packet[16*40+9: 16*40+9+696].hex()
            # print(SessionInstance.get_instance().scfg)
        PROF = packet[16*12+14: 16*12+14+256]
        SCFG = packet[16*28+14: 16*28+14+175]
        RREJ = packet[16*39+13: 16*39+13+4]
        STTL = packet[16*40+1: 16*40+1+8]
        CRT = packet[16*40+9: 16*40+9+696]
        PUBS = packet[16*36+6: 16*36+6+35]

        SessionInstance.get_instance().peer_public_value = bytes.fromhex(PUBS[3:].hex())
        # print(SessionInstance.get_instance().peer_public_value)
        return packet

        # 20000079d756bbc5a0d69634141ba4327d547e91da42c84590855ea0308e0ca6baaa16 : value of REJ PUBS


    def send_full_chlo(self):

        fullchlo = FullCHLOPacket()



        fullchlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        fullchlo.setfieldval('SCID_Value', SessionInstance.get_instance().server_config_id)
        fullchlo.setfieldval('STK_Value', string_to_ascii(self.server_adress_token.hex()))
        fullchlo.setfieldval('SNO_Value', string_to_ascii(self.server_nonce.hex()))
        fullchlo.setfieldval('SCID_Value', string_to_ascii(self.server_connection_id.hex())) #incomplete


        epochtime = str(hex(int(time.time())))
        epoch = ''.join([epochtime[i:i+2] for i in range(0,len(epochtime),2)][1:][::-1])
        sORBIT = '0'*16
        randomString = bytes.hex(os.urandom(20))

        NONC = epoch + sORBIT + randomString
        SessionInstance.get_instance().client_nonce = NONC
        fullchlo.setfieldval('NONC_Value',string_to_ascii(NONC))

        # Lets just create the public key for DHKE
        dhke.set_up_my_keys()

        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        fullchlo.setfieldval("Packet_Number", string_to_ascii(str("%02x" % packet_number)))

        fullchlo.setfieldval('PUBS_Value', string_to_ascii(SessionInstance.get_instance().public_values_bytes)) #incomplete


        associated_data = extract_from_packet(fullchlo, end=10)
        body = extract_from_packet(fullchlo, start=22)

        message_authentication_hash = FNV128A().generate_hash(associated_data, body)
        fullchlo.setfieldval('Message_Authentication_Hash', string_to_ascii(message_authentication_hash))


        SessionInstance.get_instance().chlo = extract_from_packet_as_bytestring(fullchlo, start=28, end=1052)

        conf.L3socket = L3RawSocket

        # print("Send full CHLO")
        try:
            p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=DPORT, sport=61250) / fullchlo

            ans, unans = sr(p, timeout=self.TIMEOUT)

            packet = bytes(ans[0][1][UDP][Raw])
            div_nonce = packet[9:9+32]
            packet_number = packet[41]
            print("\nnonce :",div_nonce.hex())
            ciphertext = packet[42:]
            # print("key :",SessionInstance.get_instance().peer_public_value)
            derived_key = dhke.generate_keys(SessionInstance.get_instance().peer_public_value, False)
            print("\nCipher : ",ciphertext.hex())
            diversed_key = dhke.diversify(derived_key['key2'], derived_key['iv2'], div_nonce)
            print("\nCipher : ",diversed_key)
            aesg_nonce = diversed_key['diversified_iv'] + bytes.fromhex(str("%02x" % packet_number)) + bytes.fromhex("000000") + bytes.fromhex("00000000")
            print("\nCipher : ",aesg_nonce)
            decoder = AES.new(diversed_key['diversified_key'], AES.MODE_GCM, aesg_nonce)
            # print(decoder)
            plain_text = decoder.decrypt(ciphertext)
            print("Plain : ",plain_text)

            packet_type = packet[16+10: 16+10+3]
            if packet_type ==b'REJ':
                self.server_adress_token = packet[16*5+10: 16*5+10+60]
                self.server_connection_id = packet[16*35+2: 16*35+2+16]
                self.server_nonce = packet[16*9+6: 16*9+6+56]

            return packet
        except:
            return b"EXP"
        



    def send_full_chlo_to_existing_connection(self):

        PacketNumberInstance.get_instance().reset()
        SessionInstance.get_instance().connection_id = str(format(random.getrandbits(64), 'x').zfill(16))
        

        fullchlo = FullCHLOPacket()



        fullchlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        # fullchlo.setfieldval('SCID_Value', SessionInstance.get_instance().server_config_id)
        fullchlo.setfieldval('STK_Value', string_to_ascii("4db852efc85461e7b51edf3dbb19883ac8fc87c8adec7978876b960f30b079753ded4cdae5a274309966cffb04b9b158b177a9a3ef711f2ed96de63f"))
        fullchlo.setfieldval('SNO_Value', string_to_ascii("b9f4094620cf73adbe984450c3f40ad252839ab9e2852fc888014290a58e0d598ba33d29203fab9934ccbc31eef86b3080d8fa444e049dd7"))
        fullchlo.setfieldval('SCID_Value', string_to_ascii("c24d7f4ed8ba037e77c7dbcd1ca6e9bf")) #incomplete


        # fullchlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        # fullchlo.setfieldval('SCID_Value', SessionInstance.get_instance().server_config_id)
        # fullchlo.setfieldval('STK_Value', string_to_ascii(self.server_adress_token.hex()))
        # # fullchlo.setfieldval('SNO_Value', string_to_ascii(self.server_nonce.hex()))
        # fullchlo.setfieldval('SCID_Value', string_to_ascii(self.server_connection_id.hex())) #incomplete


        epochtime = str(hex(int(time.time())))
        epoch = ''.join([epochtime[i:i+2] for i in range(0,len(epochtime),2)][1:][::-1])
        sORBIT = '0'*16
        randomString = bytes.hex(os.urandom(20))

        NONC = epoch + sORBIT + randomString

        fullchlo.setfieldval('NONC_Value',string_to_ascii(NONC))

        # Lets just create the public key for DHKE
        dhke.set_up_my_keys()

        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        fullchlo.setfieldval("Packet_Number", string_to_ascii(str("%02x" % packet_number)))

        fullchlo.setfieldval('PUBS_Value', string_to_ascii(SessionInstance.get_instance().public_values_bytes)) #incomplete


        associated_data = extract_from_packet(fullchlo, end=10)
        body = extract_from_packet(fullchlo, start=22)

        message_authentication_hash = FNV128A().generate_hash(associated_data, body)
        fullchlo.setfieldval('Message_Authentication_Hash', string_to_ascii(message_authentication_hash))

        conf.L3socket = L3RawSocket
        SessionInstance.get_instance().chlo = extract_from_packet_as_bytestring(fullchlo, start=31)   # CHLO from the CHLO tag, which starts at offset 26 (22 header + frame type + stream id + offset)

        # print("Send full CHLO")
        try:
            p = IP(dst=SessionInstance.get_instance().destination_ip) / UDP(dport=DPORT, sport=61250) / fullchlo

            ans, unans = sr(p, timeout=self.TIMEOUT)

            
            packet = bytes(ans[0][1][UDP][Raw])

            # packet_type = packet[16+10: 16+10+3]
            # if packet_type ==b'REJ':
            #     self.server_adress_token = packet[16*5+10: 16*5+10+60]
            #     self.server_connection_id = packet[16*35+2: 16*35+2+16]
            #     self.server_nonce = packet[16*9+6: 16*9+6+56]

            return packet
        except:
            return b"EXP"

    def send(self, command):
        try:
            if isinstance(command, ResetEvent):
                print("Resetting received")
                return self.send_chlo(True)
            if isinstance(command, SendInitialCHLOEvent):
                print("Sending CHLO")
                return self.send_chlo(False)
            elif isinstance(command, SendFullCHLOEvent):
                print("Sending Full CHLO")
                return self.send_full_chlo()
            elif isinstance(command, ZeroRTTCHLOEvent):
                print("Sending Zero RTT CHLO")
                return self.send_full_chlo_to_existing_connection()
            else:
                print("Unknown command {}".format(command))
        except Exception as err:
            self.logger.exception(err)



s = Scapy()
s.send(SendInitialCHLOEvent())
s.send(SendFullCHLOEvent())
# time.sleep(60)
# print(s.send(SendFullCHLOEvent()))
# print(s.send(SendInitialCHLOEvent()))
# print(s.send(ZeroRTTCHLOEvent()))

# try:
#     operations = [(s.send_chlo, False), (s.send_full_chlo, True), (s.send_full_chlo_to_existing_connection, True), (s.send_encrypted_request, True), (s.close_connection, True), (s.reset, False)]
#     print("Starting now {}".format(time.time()))
#     for i in range(2):
#         random.shuffle(operations)
#         for operation, encrypted in operations:
#             print("PERFORMING OPERATION {}".format(operation))
#             operation()
#             print("FINISHED OPERATION {}".format(operation))
#             time.sleep(2)
# except:
#     print("Fail")
# # print("Done?!")
# times = []
# for i in tqdm(range(10)):
#     s.logger.info(">>>>>>>>>>>> Starting with round {}".format(i))
#     s.logger.info("Resetting")
#     s.send(ResetEvent())
#     start = time.time()
#     # s.send(SendInitialCHLOEvent())
#     # s.send(SendGETRequestEvent())
#     # s.send(CloseConnectionEvent())
#     times.append(time.time()-start)
#     s.send(CloseConnectionEvent())
#     s.logger.info("Currently at {} out of 10".format(i))

# times = sorted(times)
# s.logger.info("All execution times {}".format(times))
# s.logger.info("Median execution time is {}".format(median(times)))

# s.send(ResetEvent())
# s.send(ZeroRTTCHLOEvent())
#     s.send(SendGETRequestEvent())
#     s.send(ResetEvent())
# s.send(ZeroRTTCHLOEvent())
# s.send(SendGETRequestEvent())
# s.send(SendFullCHLOEvent())
# s.send(SendInitialCHLOEvent())
# s.send(SendInitialCHLOEvent())
# s.send(SendFullCHLOEvent())
# s.send(ZeroRTTCHLOEvent())
# s.send(ZeroRTTCHLOEvent())
# s.send(ZeroRTTCHLOEvent())
# s.send(SendGETRequestEvent())
# s.send(SendInitialCHLOEvent())
