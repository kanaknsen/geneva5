import random

from layers.layer import Layer
from scapy.all import IP, fuzz, RandIP

class IPLayer(Layer):
    """
    Defines an interface to access IP header fields.
    """
    name = "IP"
    protocol = IP
    _fields = [
        'version',
        'ihl',
        'tos',
        'len',
        'id',
        'flags',
        'frag',
        'ttl',
        'proto',
        'chksum',
        'src',
        'dst',
        'load'
    ]
    fields = _fields

    def __init__(self, layer):
        """
        Initializes the IP layer.
        """
        Layer.__init__(self, layer)
        self.getters = {
            "flags" : self.get_flags,
            "load"  : self.get_load
        }
        self.setters = {
            "flags" : self.set_flags,
            "load"  : self.set_load
        }
        self.generators = {
            "src"    : self.gen_ip,
            "dst"    : self.gen_ip,
            "chksum" : self.gen_chksum,
            "len"    : self.gen_len,
            "load"   : self.gen_load,
            "flags"  : self.gen_flags
        }
def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (ord(data[i]) << 8) + (ord(data[i + 1]))
    if n:
        s += (ord(data[i + 1]) << 8)
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xFFFF
    return s


def sendOnePing(seq, dest_addr, ttl, timeout=2, packetsize=64):
    if packetsize:
        ICMP_LEN_BYTES = packetsize
    else:
        ICMP_LEN_BYTES = 64

    socket.setdefaulttimeout(timeout)
    try:
        icmp = socket.getprotobyname('icmp')
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    except socket.error, (errno, msg):
        if errno == 1:
            msg = "%s : running as root" % msg
            raise socket.error(msg)

    ICMP_ECHO_REQUEST = 8
    ICMP_CODE = 0
    ICMP_ID = os.getpid() & 0xFFFF
    ICMP_CHECKSUM = 0
    ICMP_SEQ = seq

    dest_addr = socket.gethostbyname(dest_addr)
    # 1字节类型 1字节代码 2字节checksum 2字节标识符 2字节序号
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST,
        ICMP_CODE, ICMP_CHECKSUM, ICMP_ID, ICMP_SEQ)
    bytesInDouble = struct.calcsize("d")
    data = "%s%s" % (
        "Medici.Yan", (
            ICMP_LEN_BYTES - len('Medici.Yan') - bytesInDouble) * "M")
    data = struct.pack("d", time.time()) + data

    ICMP_CHECKSUM = checksum(header + data)

    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, ICMP_CODE,
        socket.htons(ICMP_CHECKSUM), ICMP_ID, ICMP_SEQ)

    packet = header + data

    s.sendto(packet, (dest_addr, 0))

    while True:
        try:
            recPacket, addr = s.recvfrom(1024)
            timeReceived = time.time()
            icmpHeader = recPacket[20:28]
            _type, _code, _checksum, _packetID, _sequence = struct.unpack(
                'bbHHh', icmpHeader)
            if _packetID == ICMP_ID:
                _ttl = struct.unpack("B", recPacket[8])[0]
                timeSent = struct.unpack(
                    "d", recPacket[28:28 + bytesInDouble])[0]
                delay = (timeReceived - timeSent) * 1000
                print (
                    "%d Bytes from %s : icmp_seq=%d ttl=%d time=%0.4fms"
                    % (len(recPacket)-28, addr[0], ICMP_SEQ, _ttl, delay))
                time.sleep(1)
                return delay
        except socket.timeout:
            print "Request timeout for icmp_seq %d" % (ICMP_SEQ)
            return False
        except Exception, e:
            raise e


def ping(conf):
    count = conf['count']
    ttl = conf['ttl']
    host = conf['host']
    packetsize = conf['packetsize']
    timeout = conf['timeout']
    dest_addr = socket.gethostbyname(host)
    if not packetsize or packetsize < 11:
        packetsize = 64
    if not count:
        count = 3
    if not timeout:
        timeout = 2
    print "PING %s(%s): %s data bytes" % (host, dest_addr, packetsize)
    result = []
    try:
        for i in range(count):
            delay = sendOnePing(
                seq=i, dest_addr=dest_addr, ttl=ttl,
                timeout=timeout, packetsize=packetsize)
            result.append(delay)
    except:
        pass
    finally:
        statisticPing(result, host)





    def gen_len(self, field):
        """
        Generates a valid IP length. Scapy breaks if the length is set to 0, so
        return a random int starting at 1.
        """
        return random.randint(1, 500)

    def gen_chksum(self, field):
        """
        Generates a checksum.
        """
        return random.randint(1, 65535)

    def gen_ip(self, field):
        """
        Generates an IP address.
        """
        return RandIP()._fix()

    def get_flags(self, field):
        """
        Retrieves flags as a string.
        """
        return str(self.layer.flags)

    def set_flags(self, packet, field, value):
        """
        Sets the flags field. There is a bug in scapy, if you retrieve an empty
        flags field, it will return "", but you cannot set this value back.
        To reproduce this bug:

        .. code-block:: python

           >>> setattr(IP(), "flags", str(IP().flags)) # raises a ValueError

        To handle this case, this method converts empty string to zero so that
        it can be safely stored.
        """
        if value == "":
            value = 0
        self.layer.flags = value

    def statisticPing(result, host):
    ping_count = len(result)
    failnum = result.count(False)
    max_time = 0
    min_time = 0
    ave_time = 0
    lostdegree = 0
    for i in range(failnum):
        result.remove(False)
    if result:
        max_time = max(result)
        min_time = min(result)
        ave_time = sum(result) / (ping_count - failnum)
    res = "--- %s ping statistics ---\n"
    res = res + "%d packets transmitted, %d packets received, %0.1f%% "
    res = res + "packet loss\nround-trip min/avg/max = %0.4f/%0.4f/%0.4f ms"
    
    if ping_count != 0:
        lostdegree = (1.0 * failnum / ping_count) * 100
    print res % (
        host, ping_count, (ping_count - failnum), lostdegree,
        min_time, ave_time, max_time)
    

    def gen_flags(self, field):
        """
        Generates random valid flags.
        """
        sample = fuzz(self.protocol())

        # Since scapy lazily evaluates fuzzing, we first must set a
        # legitimate value for scapy to evaluate what combination of flags it is
        sample.flags = sample.flags

        return str(sample.flags)
