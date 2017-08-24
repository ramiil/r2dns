import socket
import sqlite3

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

  def getIpByName(self, dn):
    if (dn=='myself.global'):
      return '255.255.255.255'
    else:
      self.cursor.execute("SELECT target FROM Records WHERE base='"+dn+"' AND type='A'")
      rezult = self.cursor.fetchall()
    if rezult:
      return rezult[0][0]
    else:
      return '0.0.0.0'

class DNSQuery:
  def __init__(self, data, clientIP):
    self.data=data
    self.domain=''

    if getbit(ord(data[2]), 1) == 0:	# Standard query
      ptr=12				# Pointer to first address block length
      length=ord(data[ptr])		# Length of first address block
      while length != 0:
	self.domain+=data[ptr+1:ptr+length+1]+'.'
	ptr+=length+1
	length=ord(data[ptr])

  def parseQuery(self):
    print " ".join("{:02x}".format(ord(c)) for c in self.data)
    print "ID:"+" ".join("{:02x}".format(ord(c)) for c in self.data[0:2])
    print "FLAGS: "+" ".join("{:02x}".format(ord(c)) for c in self.data[2:4])
    print "QueN: "+" ".join("{:02x}".format(ord(c)) for c in self.data[4:6])
    print "AnsN: "+" ".join("{:02x}".format(ord(c)) for c in self.data[6:8])
    print "NSN: "+" ".join("{:02x}".format(ord(c)) for c in self.data[8:10])
    print "ARC: "+" ".join("{:02x}".format(ord(c)) for c in self.data[10:12])
    print "ptr: "+" ".join("{:02x}".format(ord(c)) for c in self.data[12:13])

  def answer(self, ip):
    self.parseQuery()
    packet=''
    if self.domain:
      if (ip=='255.255.255.255'):  		# We need return client's IP instead
        ip=self.clientIP
      if (ip=='0.0.0.0'):
        packet+=self.data[:2] + "\x81\x83" 	# We need return NXDOMAIN
      else:
        packet+=self.data[:2] + "\x85\x80" 	# We need return requested domain's IP
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Requests and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Request
      packet+='\xc0\x0c'                                             # Pointer to domain name block start
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
      print ' Answer: ',self.domain,' -> ',ip
      #print " ".join("{:02x}".format(ord(c)) for c in packet)
    return packet

udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udps.bind(('',53))

ns=NameStoarge('dns.sqlite')

try:
  while 1:
    qData, clAddr = udps.recvfrom(1024)
    print "New request from ",clAddr[0]
    ipHash = socket.inet_aton(clAddr[0])
    #print map(lambda x: x.encode('hex'), ipHash)
    dnsq=DNSQuery(qData, clAddr[0])
    udps.sendto(dnsq.answer(ns.getIpByName(dnsq.domain[:len(dnsq.domain)-1])), clAddr)

except KeyboardInterrupt:
  udps.close()
