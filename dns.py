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

  def make_domain(self, domain):
    return "".join(map(lambda x: chr(len(x)) + x, domain.split("."))) + '\x00'

  def answer(self, query_type):
    packet = ''
    domain = ''
    ip = ''
    print "Query type: " + query_type
    if query_type == "A":
      domain = self.get_domain()
      ip = ns.get_ip_by_domain(domain[:-1])
      if ip == "0.0.0.0":
        # We need return original query's ID + NXDOMAIN
        packet += self.data[:2] + "\x81\x83"
      else:
        # We need return original query's ID + requested domain's IP
        packet += self.data[:2] + "\x85\x80"

      # Count of queries, answers, ns servers, additional records
      packet += self.data[4:6] + self.data[4:6] + '\x00\x01\x00\x01'

      # Original Domain Name Request
      packet += self.data[12:]

      # Pointer to domain name block start
      packet += '\xc0\x0c'

      # Response type, ttl and resource data length -> 4 bytes
      packet += '\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04'

      # 4 bytes of IP
      packet += "".join(map(lambda x: chr(int(x)), ip.split('.')))

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
    print "[" + " ".join(format(ord(c), '02x') for c in packet) + "]"
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
    if not query_data:
      conn, client_address = tcp_socket.accept()
      query_data = conn.recv(1024)
      print "New request from TCP/" + client_address[0]
      dns_query = DNSQuery(query_data)
      conn.send(dns_query.answer(dns_query.get_query_type()))

    else:
      print "New request from UDP/" + client_address[0]
      dns_query = DNSQuery(query_data)
      udp_socket.sendto(dns_query.answer(dns_query.get_query_type()), client_address)

except KeyboardInterrupt:
  udp_socket.close()
