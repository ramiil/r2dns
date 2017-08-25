import socket
import sqlite3

nameserver="bkz.kdt.moe"

def setbit(number, index):
  number |= (1<<index)
  return number

def unsetbit(number, index):
  number &= ~(1<<index)
  return number

def getbit(number, index):
  return int(number&(1<<index)!=0)

class NameStoarge:
  def __init__(self, dbFile):
    self.db = sqlite3.connect(dbFile)
    self.cursor = self.db.cursor()

  def getIpByDomain(self, dn):
    if (dn=='myself.global'):
      return clAddr[0]
    else:
      self.cursor.execute("SELECT target FROM Records WHERE base='"+dn+"' AND type='A'")
      rezult = self.cursor.fetchall()
    if rezult:
      return rezult[0][0]
    else:
      return "0.0.0.0"

  def getDomainByIP(self, ip):
    self.cursor.execute("SELECT base FROM Records WHERE target='"+ip+"' AND type='A'")
    rezult = self.cursor.fetchall()
    if rezult:
      return rezult[0][0]
    else:
      return "NXDOMAIN"

  def getNS(self, dn):
    self.cursor.execute("SELECT target FROM Records WHERE base='"+dn+"' AND type='A'")
    rezult = self.cursor.fetchall()
    if rezult:
      print "NS found"
      return nameserver
    else:
      return "NXDOMAIN"

class DNSQuery:
  def __init__(self, data):
    print "["+" ".join("{:02x}".format(ord(c)) for c in data)+"]"
    self.data=data

  def getQueryType(self):
    queryType="Unknown"
    ptr=12
    length=ord(self.data[ptr])
    while (length!=0):
      ptr+=length+1
      length=ord(self.data[ptr])
    queryCode = " ".join(format(ord(c), '02X') for c in self.data[ptr+1:ptr+3])
    print queryCode
    if (queryCode=="00 01"):
      queryType="A"
    if (queryCode=="00 02"):
      queryType="NS"
    if (queryCode=="00 05"):
      queryType="CNAME"
    if (queryCode=="00 06"):
      queryType="SOA"
    if (queryCode=="00 0C"):
      queryType="PTR"
    if (queryCode=="00 0F"):
      queryType="MX"
    if (queryCode=="00 10"):
      queryType="TXT"
    if (queryCode=="00 1C"):
      queryType="AAAA"
    return queryType

  def getDomain(self):
    domain=''
    if getbit(ord(self.data[2]), 1) == 0:	# Standard query
      ptr=12					# Pointer to first address block length
      length=ord(self.data[ptr])		# Length of first address block
      while length != 0:
	domain+=self.data[ptr+1:ptr+length+1]+'.'
	ptr+=length+1
	length=ord(self.data[ptr])
    return domain

  def makeDomain(self, domain):
    return "".join(map(lambda x:chr(len(x))+x, a.split(".")))+'\x00'
    

  def answer(self, qtype):
    packet=''
    domain=''
    ip=''
    print qtype
    if (qtype=="A"):
      domain = self.getDomain()
      ip = ns.getIpByDomain(domain[:-1])
      if (domain=="0.0.0.0"):
	packet+=self.data[:2] + "\x81\x83" 	# We need return original query's ID + NXDOMAIN
      else:
	packet+=self.data[:2] + "\x85\x80" 	# We need return original query's ID + requested domain's IP
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x01'   # Count of queries, answers, ns servers, additional records
      packet+=self.data[12:]                                         # Original Domain Name Request
      packet+='\xc0\x0c'                                             # Pointer to domain name block start
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+="".join(map(lambda x: chr(int(x)), ip.split('.')))	# 4bytes of IP

    if (qtype=="NS"):
      domain = self.getDomain()
      namesrv = ns.getNS(domain[:-1])
      if (domain=="0.0.0.0"):
	packet+=self.data[:2] + "\x81\x83" 	# We need return original query's ID + NXDOMAIN
      else:
	packet+=self.data[:2] + "\x85\x80" 	# We need return original query's ID + requested domain's IP
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x01'   	# Count of queries, answers, ns servers, additional records
      packet+=self.data[12:]                                         	# Original Domain Name Request
      packet+='\xc0\x0c'                                             	# Pointer to domain name block start
      packet+='\x00\x02\x00\x01\x00\x00\x00\x3c\x00'+chr(len(namesrv))  # Response type, ttl and resource data length -> 4 bytes
      packet+="".join(map(lambda x:chr(len(x))+x, namesrv.split(".")))+'\x00' # 4bytes of IP

    print ' Answer: '+domain+' -> '+ip
    print "["+" ".join("{:02x}".format(ord(c)) for c in packet)+"]"
    return packet

udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udps.bind(('',53))

ns=NameStoarge('dns.sqlite')

try:
  while 1:
    qData, clAddr = udps.recvfrom(1024)
    print "New request from ",clAddr[0]
    dnsq=DNSQuery(qData)
    udps.sendto(dnsq.answer(dnsq.getQueryType()), clAddr)

except KeyboardInterrupt:
  udps.close()
