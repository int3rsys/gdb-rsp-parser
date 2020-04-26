import binascii
import packet_parser

NOT_COMPLETE_SEQUENCE=255
BAD_PACKET=254

def checksum(packet):
    packet_sum=0
    for byte in packet:
        packet_sum+=byte
    return packet_sum % 256

def check_integrity(pkt):
    start = pkt[:1]
    end = pkt[-3:-2]
    if checksum(pkt[:-3]) != int(pkt[-2:],16):
        return False
    return True

def read_packet(packet):
    if(packet[-3] != 35):
        return NOT_COMPLETE_SEQUENCE
    correct_integrity = check_integrity(packet)
    if correct_integrity:
        return True
    else:
        return BAD_PACKET

def readfile(filepath):
    with open(filepath, 'r', encoding='windows-1252') as file:
        data = '\n'.join(file.readlines())
    return data

def decode_data(data):
    data = data.replace('\n', '').replace('\r', '').replace('+','')
    data = binascii.unhexlify(data)
    data = data.split(b'$')
    return data

data = decode_data(readfile('<yourfilehere>')) #file should contain raw hex data
partial_packet=b""
ignore_packet = False
response=False
for packet in data:
    if partial_packet != b"":
        # The packet contains an escape char
        packet = partial_packet+packet
        partial_packet=b""
    if len(packet)>1 or ignore_packet:
        if packet[-1] == ord(b'+'):
            packet=packet[:-1]
            response = False
        if packet[-1] == ord(b'-'):
            next_packet = data.index(packet)+1
            ignore_packet = True
            print("[*] Packet {} was requested to be retransmitted. Ignoring it.".format(next_packet))
            response = False

        ignore_packet = False
        return_value = read_packet(packet)
        if return_value == BAD_PACKET:
            print("[*] Packet {} is corrupted".format(packet))
        elif return_value == NOT_COMPLETE_SEQUENCE:
            partial_packet = packet + b'$'
        else:
            packet = packet[:-3]
            if not packet == b'': #there is no point in sending an empty packet...
                parser = packet_parser.parser(packet)
                parsed_msg = parser.get_parsed_packet()()
                print(parsed_msg)
