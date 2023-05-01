
import struct
import dpkt


# a method used to ensure the source port and destination port are corresponding
def port_check(p1, p2):
    if p1.srcPort == p2.destPort and p2.srcPort == p1.destPort:
        return True
    if p1.srcPort == p2.srcPort and p2.destPort == p1.destPort:
        return True
    return False


# to check if connection was set up (in the condition of when both of syn and ack are 1, it will be considered as connected)
def ack_check(p):
    if p.syn == "1" and p.ack == "1":
        return True
    return False


# a method to identify the source ip address and the destination ip address
def tcp_check(parse, source_ip, destination_ip):
    if parse.srcIP == source_ip and parse.destIP == destination_ip:
        return True
    return False

# to get the data from packets and convert it to String form then we can directly parse it in our own structure


def getByte(buffer, a, position, size):
    if (len(buffer) > position):
        return str(struct.unpack(a, buffer[position:position + size])[0])


class tcp:

    isTCP = True
    timestamp = 0   # initialization
    srcIP = ""
    destIP = ""
    srcPort = ""
    destPort = ""
    seqNumber = ""
    ackNumber = ""
    syn = ""
    ack = ""
    headerSize = ""
    windowSize = ""
    size = ""

    #  a method to parse the packet
    def parse_packet(parse, timestamp, buffer):
        try:
            # parse the source ip address and destination ip address from header
            x, y = 26, 30
            while x < 29:
                parse.srcIP = parse.srcIP + getByte(buffer, ">B", x, 1) + "."
                parse.destIP = parse.destIP + getByte(buffer, ">B", y, 1) + "."
                x = x + 1
                y = y + 1
            parse.srcIP = parse.srcIP + getByte(buffer, ">B", x, 1)
            parse.destIP = parse.destIP + getByte(buffer, ">B", y, 1)

            # parse the source port and destination port from header
            parse.srcPort = getByte(buffer, ">H", 34, 2)
            parse.destPort = getByte(buffer, ">H", 36, 2)

            # parse sequence number and acknowledgement number
            parse.seqNumber = getByte(buffer, ">I", 38, 4)
            parse.ackNumber = getByte(buffer, ">I", 42, 4)

            # parse header size , ack and syn
            parse.headerSize = getByte(buffer, ">B", 46, 1)
            parse.ack = "{0:16b}".format(int(getByte(buffer, ">H", 46, 2)))[11]
            parse.syn = "{0:16b}".format(int(getByte(buffer, ">H", 46, 2)))[14]

            # parse window size, size and timestamp
            parse.windowSize = getByte(buffer, ">H", 48, 2)
            parse.size = len(buffer)
            parse.timestamp = timestamp
        except:
            parse.isTCP = False


class Connection:
    packets = []
    srcPort = ""
    destPort = ""

    def __init__(parse, src, dest):
        parse.srcPort = src
        parse.destPort = dest


# method to calculate the throughput
def get_throuput(transmission):
    total_data = 0
    first_byte = 0
    last_byte = 0
    throughput = 0
    total_time = 0
    i = 0
    start_packet = True
    # store the timestamp of the first packet was sent, then calculate the total data sent by dividing the last byte sent timestamp minus first timestamp
    for parse in transmission.packets:
        if parse.srcIP == "130.245.145.12":
            if start_packet:
                first_byte = parse.timestamp
                start_packet = False
            else:
                if i < 3:  # for 3 connections
                    if i != 0:
                        print("Sequence Number: " + parse.seqNumber +"      Acknowledgement Number:  " + parse.ackNumber+
                        "      Window size: "+ parse.windowSize)
                    i += 1
                total_data = total_data + int(parse.size)
                last_byte = parse.timestamp
                total_time = (last_byte-first_byte)
    #  throughput = total data receive / total time
    throughput = total_data / total_time

    return throughput


#  method to calculate triple ack loss and time out loss
def loss_of_ack_timeout(transmission):
    loss = 0
    triple_ack_loss = 0
    seqdict = {}  # initialize sequence dictionary
    ackdict = {}  # initialize ack dictionary

    for parse in transmission.packets:
        # calculate every retransmission due to duplicate from these two particular sender to receiver
        if tcp_check(parse, "130.245.145.12", "128.208.2.198"):
            seqdict[parse.seqNumber] = seqdict.get(parse.seqNumber, 0) + 1

        if tcp_check(parse, "128.208.2.198", "130.245.145.12"):
            ackdict[parse.ackNumber] = ackdict.get(parse.ackNumber, 0) + 1

    for key, value in seqdict.items():
        # for every ack number appears more than 2 ,we consider it as triple_ack_loss
        if (key in ackdict) and (ackdict[key] > 2):
            triple_ack_loss = triple_ack_loss + seqdict[key] - 1
        # for other loss, we consider it as time out loss
        elif key in seqdict:
            loss = loss + seqdict[key] - 1

    print("Retransmission due to Triple Acknowledgement : %s " % str(triple_ack_loss))
    print("Retransmission due to Timeout : %s" % str(loss))


# method to calculate congestion window size
def cwnd(transmission):
    times = 0
    start_packet = True
    start_timestamp = 0
    i = 0

    for parse in transmission.packets:
        if i > 3:
            break
        if tcp_check(parse, "130.245.145.12", "128.208.2.198"):
            times = times + 1
            if start_packet:
                start_timestamp = parse.timestamp
                start_packet = False
            # 0.07307 is the approximately average RTT I calculated
            elif (parse.timestamp - start_timestamp) > 0.07307:
                if i != 0:
                    print("Congestion Window = %s " % (times * 1460))
                times = 0
                start_packet = True
                i = i+1




if __name__ == '__main__':
    i = 1
    packets = []
    transmission = []
    for timestamp, buffer in dpkt.pcap.Reader(open('assignment2.pcap', 'rb')):
        p = tcp()
        p.parse_packet(timestamp, buffer)
        if p.isTCP:
            packets.append(p)
            if ack_check(p):
                connection = Connection(p.srcPort, p.destPort)
                connection.packets = []
                transmission.append(connection)

    for p in packets:
        for connection in range(0, len(transmission), 1):
            if port_check(p, transmission[connection]):
                transmission[connection].packets.append(p)

    print("\n")
    for connection in transmission:
        print("TCP Connection  %s" % i)
        print("========================================================================")
        print("\n")
        print("Source IP Address: " + p.srcIP + "            Destination IP Address: " + p.destIP)
        print("Source Port: " + connection.destPort + "                           Destination Port: " + connection.srcPort)
        print("\n")
        print("Throughput : %s Bytes/second" % (get_throuput(connection)))
        print("\n")
        cwnd(connection)
        loss_of_ack_timeout(connection)
        print("\n")
        i = i + 1


