import socket
import sqlite3

nameserver = ["bkz1.kdt.moe.", "bkz2.kdt.moe"]


def set_bit(number, index):
    number |= (1 << index)
    return number


def unset_bit(number, index):
    number &= ~(1 << index)
    return number


def get_bit(number, index):
    return int(number & (1 << index) != 0)


class NameStorage:
    def __init__(self, db_file):
        self.db = sqlite3.connect(db_file)
        self.cursor = self.db.cursor()

    def get_ip_by_domain(self, dn):
        if dn == 'myself.global':
            return client_address[0]
        else:
            self.cursor.execute("SELECT target FROM Records WHERE base='" + dn + "' AND type='A'")
            result = self.cursor.fetchall()
        if result:
            return result[0][0]
        else:
            return "0.0.0.0"

    def get_domain_by_ip(self, ip):
        self.cursor.execute("SELECT base FROM Records WHERE target='" + ip + "' AND type='A'")
        result = self.cursor.fetchall()
        if result:
            return result[0][0]
        else:
            return "NXDOMAIN"

    def get_ns(self, dn):
        self.cursor.execute("SELECT target FROM Records WHERE base='" + dn + "' AND type='A'")
        result = self.cursor.fetchall()
        if result:
            return nameserver
        else:
            return "NXDOMAIN"


class DNSQuery:
    def __init__(self, data):
        print "[" + " ".join(format(ord(c), '02X') for c in data) + "]"
        self.data = data

    def get_query_type(self):
        query_type = "Unknown"
        ptr = 12
        length = ord(self.data[ptr])
        while length != 0:
            ptr += length + 1
            length = ord(self.data[ptr])

        query_code = " ".join(format(ord(c), '02X') for c in self.data[ptr + 1:ptr + 3])

        # print query_code
        if query_code == "00 01":
            query_type = "A"
        elif query_code == "00 02":
            query_type = "NS"
        elif query_code == "00 05":
            query_type = "CNAME"
        elif query_code == "00 06":
            query_type = "SOA"
        elif query_code == "00 0C":
            query_type = "PTR"
        elif query_code == "00 0F":
            query_type = "MX"
        elif query_code == "00 10":
            query_type = "TXT"
        elif query_code == "00 1C":
            query_type = "AAAA"
        return query_type

    def get_domain(self):
        domain = ''
        if get_bit(ord(self.data[2]), 1) == 0:
            # Standard query

            # Pointer to first address block length
            ptr = 12

            # Length of first address block
            length = ord(self.data[ptr])

            while length != 0:
                domain += self.data[ptr + 1:ptr + length + 1] + '.'
                ptr += length + 1
                length = ord(self.data[ptr])

        return domain

    @staticmethod
    def make_domain(domain):
        return "".join(map(lambda x: chr(len(x)) + x, domain.split("."))) + '\x00'

    def parse_request(self, data):
        query = data
        id = query[:2]
        query = query[2:]

        flags = query[:2]
        query = query[2:]

        question_count = ord(query[0]) * 255 + ord(query[1])
        query = query[2:]

        answer_count = ord(query[0]) * 255 + ord(query[1])
        query = query[2:]

        authority_count = ord(query[0]) * 255 + ord(query[1])
        query = query[2:]

        additional_count = ord(query[0]) * 255 + ord(query[1])
        query = query[2:]

        # Questions parser
        questions = []
        for i in xrange(0, question_count, 1):
            # pointer: 0x0c
            # question_pointer = query[:1]
            # query = query[1:]

            tmp = ''
            for j in xrange(0, len(query), 1):
                if query[j] == '\x00':
                    query = query[j + 1:]
                    break
                else:
                    tmp += query[j]

            q_type = query[:2]
            query = query[2:]
            q_class = query[:2]
            query = query[2:]

            questions.append({
                'name': tmp,
                'q_type': q_type,
                'q_class': q_class
            })

        # TODO: Authorities parsing

        # Additionals parser
        additionals = []
        for i in xrange(0, additional_count, 1):
            tmp = {}
            tmp['name'] = query[:1]
            query = query[1:]
            tmp['type'] = query[:2]
            query = query[2:]
            if tmp['type'] == '\x00\x29':
                # Type: OPT
                tmp['payload_size'] = query[:2]
                query = query[2:]
                tmp['rcode'] = query[:1]
                query = query[1:]
                tmp['edns0_ver'] = query[:1]
                query = query[1:]
                tmp['z'] = query[:2]
                query = query[2:]
                tmp['data_len'] = query[:2]
                query = query[2:]
            additionals.append(tmp)

        return {
            'id': id,
            'flags': flags,
            'questions': questions,
            'answers': [],
            'authorities': [],
            'additionals': additionals
        }

    def answer(self, query_type):
        packet = ''
        domain = ''
        ip = ''
        request = self.parse_request(self.data)

        question_count = format(len(request['questions']), '#06x')
        question_count = question_count[2:]
        additionals_count = format(len(request['additionals']), '#06x')
        additionals_count = additionals_count[2:]

        print "Query type: " + query_type
        if query_type == "A":
            domain = self.get_domain()
            ip = ns.get_ip_by_domain(domain[:-1])
            if ip == "0.0.0.0":
                # Original query ID
                packet += request['id']

                # Status: NXDOMAIN
                packet += '\x80\x03'

                # Flags
                packet += question_count.decode('hex')  # Questions
                packet += '\x00\x00'  # Answers
                packet += '\x00\x00'  # Authority RRs TODO: implement
                packet += additionals_count.decode('hex')  # Additional RRs

                # Questions
                for i in xrange(0, len(request['questions']), 1):
                    packet += request['questions'][0]['name']
                    packet += '\x00'
                    packet += request['questions'][0]['q_type']
                    packet += request['questions'][0]['q_class']

                # Answers
                # No answers

                # Authorities
                # TODO: implement

                # Additionals
                # Original Domain Name Requests
                for i in xrange(0, len(request['additionals']), 1):
                    packet += request['additionals'][i]['name']
                    packet += request['additionals'][i]['type']
                    packet += request['additionals'][i]['payload_size']
                    packet += request['additionals'][i]['rcode']
                    packet += request['additionals'][i]['edns0_ver']
                    packet += request['additionals'][i]['z']
                    packet += request['additionals'][i]['data_len']

                return packet

            # Original query ID
            packet += request['id']

            # Status: No errors
            packet += '\x81\x80'

            # Flags
            packet += question_count.decode('hex')  # Questions
            packet += '\x00\x01'  # Answers (1)
            packet += '\x00\x00'  # Authority RRs TODO: implemet
            packet += additionals_count.decode('hex')  # Additional RRs

            # Count of queries, answers, ns servers, additional records
            # packet += self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'

            # Questions
            for i in xrange(0, len(request['questions']), 1):
                packet += request['questions'][0]['name']
                packet += '\x00'
                packet += request['questions'][0]['q_type']
                packet += request['questions'][0]['q_class']

            # Pointer to domain name block start
            packet += '\xc0\x0c'

            # Response type, ttl and resource data length
            packet += '\x00\x01'  # Class: A
            packet += '\x00\x01'  # Type: IN
            packet += '\x00\x00\x00\x3c'  # TTL: 60
            packet += '\x00\x04'  # Data length: 4 bytes

            # 4 bytes of IP
            packet += "".join(map(lambda x: chr(int(x)), ip.split('.')))

            # Additionals
            for i in xrange(0, len(request['additionals']), 1):
                packet += request['additionals'][i]['name']
                packet += request['additionals'][i]['type']
                packet += request['additionals'][i]['payload_size']
                packet += request['additionals'][i]['rcode']
                packet += request['additionals'][i]['edns0_ver']
                packet += request['additionals'][i]['z']
                packet += request['additionals'][i]['data_len']

        if query_type == "NS":
            domain = self.get_domain()
            namesrv = ns.get_ns(domain[:-1])
            if namesrv == "0.0.0.0":
                # We need return original query's ID + NXDOMAIN
                packet += self.data[:2] + "\x81\x83"
            else:
                # We need return original query's ID + requested domain's IP
                packet += self.data[:2] + "\x85\x80"

            # Count of queries, answers, ns servers, additional records
            packet += self.data[4:6] + '\x00\x02\x00\x01\x00\x01'

            # Original Domain Name Request
            packet += self.data[12:]

            # Pointer to domain name block start
            packet += '\xc0\x0c'
            rdata = "".join(map(lambda x: chr(len(x)) + x, namesrv[0].split("."))) + '\x00'
            packet += '\x00\x02\x00\x01\x00\x00\x01\x2c\x00' + chr(len(rdata) - 1)
            packet += rdata
            # rdata="".join(map(lambda x:chr(len(x))+x, namesrv[1].split(".")))+'\x00'
            # packet+='\x00\x02\x00\x01\x00\x00\x01\x2c\x00'+chr(len(rdata)-1)
            # packet+=rdata

        if query_type == "SOA":
            domain = self.get_domain()
            namesrv = ns.get_ns(domain[:-1])
            if namesrv == "0.0.0.0":
                # We need return original query's ID + NXDOMAIN
                packet += self.data[:2] + "\x81\x83"
            else:
                # We need return original query's ID + requested domain's IP
                packet += self.data[:2] + "\x85\x80"

            # Count of queries, answers, ns servers, additional records
            packet += self.data[4:6] + '\x00\x01\x00\x01\x00\x01'

            # Original Domain Name Request
            packet += self.data[12:]

            # Pointer to domain name block start
            packet += '\xc0\x0c'

            rdata = ''
            rdata += "".join(map(lambda x: chr(len(x)) + x, namesrv[1].split("."))) + '\x00'
            rdata += "".join(map(lambda x: chr(len(x)) + x, namesrv[1].split("."))) + '\x00'
            rdata += '\x78\xB8\xF6\xAD'
            rdata += '\x00\x00\x27\x10'
            rdata += '\x00\x00\x09\x60'
            rdata += '\x00\x09\x3A\x80'
            packet += '\x00\x06\x00\x01\x00\x00\x01\x2c\x00' + chr(len(rdata) - 1)
            packet += rdata

        print ' Answer: ' + domain + ' -> ' + ip
        print "[" + " ".join(format(ord(c), '02X') for c in packet) + "]"
        return packet


udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

udp_socket.bind(('', 5300))
tcp_socket.bind(('', 5300))
tcp_socket.listen(1)

ns = NameStorage('dns.sqlite')

try:
    while 1:
        print ""
        query_data, client_address = udp_socket.recvfrom(1024)

        if query_data:
            print "New request from UDP/" + client_address[0]
            dns_query = DNSQuery(query_data)
            udp_socket.sendto(dns_query.answer(dns_query.get_query_type()), client_address)
        else:
            conn, client_address = tcp_socket.accept()
            query_data = conn.recv(1024)
            print "New request from TCP/" + client_address[0]
            dns_query = DNSQuery(query_data)
            conn.send(dns_query.answer(dns_query.get_query_type()))

except KeyboardInterrupt:
    udp_socket.close()
