import socket
import sqlite3

class NameStoarge:
  def __init__(self, dbFile):
    self.db = sqlite3.connect(dbFile)
    self.cursor = self.db.cursor()

  def getIpByName(self, dn):
    self.cursor.execute("SELECT target FROM Records WHERE base='"+dn+"' AND type='A'")
    rezult = self.cursor.fetchall()
    if rezult:
      return rezult[0][0]
    else:
      return '0.0.0.0'

class DNSQuery:
  def __init__(self, data):
    self.data=data
    self.domain=''

    tip = (ord(data[2]) >> 3) & 15   # Opcode bits
    if tip == 0:                     # Standard query
      ini=12
      lon=ord(data[ini])
      while lon != 0:
        self.domain+=data[ini+1:ini+lon+1]+'.'
        ini+=lon+1
        lon=ord(data[ini])

  def answer(self, ip):
    packet=''
    if self.domain:
      if (ip=='0.0.0.0'):
        packet+=self.data[:2] + "\x81\x83" # NXDOMAIN
      else:
        packet+=self.data[:2] + "\x81\x80" # OK
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
      print 'Answer: ', self.domain, ' -> ', ip
    return packet

udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udps.bind(('',53))

ns=NameStoarge('dns.sqlite')

try:
  while 1:
    qData, clAddr = udps.recvfrom(1024)
    dnsq=DNSQuery(qData)
    udps.sendto(dnsq.answer(ns.getIpByName(dnsq.domain[:len(dnsq.domain)-1])), clAddr)

except KeyboardInterrupt:
  udps.close()
