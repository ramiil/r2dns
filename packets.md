# Packet structure
```
32 ec 01 00 00 01 00 00 00 00 00 00 03 6c 6f 6c 05 74 65 73 74 00 00 01 00 01 ANSver
32 ec 81 80 00 01 00 01 00 00 00 00 03 6c 6f 6c 05 74 65 73 74 00 00 01 00 01 RESource
\___/ \___/ \___/ \___/ \___/ \___/ \/ \______/ \/ \_________/ \/ \___/ \___/
 ID    #01   QCn   ANc   NSc   ARC   3   lol     4    test     0   Qtp   Qcl
 
```

* QCn: number of queries
* ANc: number of answers
* NSc: number of NS servers
* ARC: number of additional records

Qtp is Answer TYPE part. A\PTR\MX is here
Qcl is Answer CLASS part. 00 01 is IN(Internet)

## #01:
```
0 1 2 3 4 5 6 7 8 9 A B C D E F
-------------------------------
0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 ANS
1 0 0 0 0 0 0 1 1 0 0 0 0 0 0 0 RES
1 0 0 0 0 0 0 1 1 0 0 0 0 0 1 1 RES Name Error
| \_____/ \_____/ \___/ \_____/
Q OPCODE   FLAGS    Z    RCODE
```

Q - If set, ANS, else - RES

## FLAGS
#0: AA - authority answer bit
#1: TC - truncated message flag
#2: RD - recursion flag
#3: RA - set in response if recursion enabled

```
RES ADD: c0 0c 00 01 00 01 00 00 00 3c 00 04 00 00 00 00
         \___/ \___/ \___/ \_________/ \___/ \_________/
         NAME  TYPE  CLASS     TTL     LENGTH    IP
```

## NAME
```
0 1 2 3 4 5 6 7 8 9 A B C D E F
-------------------------------
1 1 0 0 0 0 0 0 0 0 0 0 1 1 0 0
\_/ \_________________________/
PTf         POINTER
```

PTf - if both 11, all the rest is integer offset

POINTER: integer offset from the beginning of message to beginning of name record

```SQL
CREATE TABLE users(id INTEGER PRIMARY KEY, base TEXT, target TEXT, type TEXT, ttl INTEGER)
```

## RECORD:
```
BASE -> TARGET
```

## A RECORD:
```
IP -> HOSTNAME
```

```SQL
SELECT base FROM Records WHERE target='localhost' AND type='A'
```

## Packet sample
### Query
```
08 44 01 00 00 01 00 00 00 00 00 00 02 79 61 02 72 75 00 00 01 00 01
\___/ \___/ \___/ \___/ \___/ \___/ \/ \___/ \/ \___/ \/ \___/ \___/
 ID    #01   QCn   ANc   NSc   ARC   3  ya    2  ru   0   Qtp   Qcl
```

### Answer

```
a9 e1 85 80 00 01 00 01 00 00 00 01 04 74 65 73 74 03 74 6c 64 00 00 02 00 01 c0 0c 00 01 00 01 00 00 00 3c 00 04 04 62 6b 7a 32 03 6b 64 74 03 6d 6f 65 00
\___/ \___/ \___/ \___/ \___/ \___/ \/ \_________/ \/ \______/ \/ \___/ \___/ \_________________________________/ \/ \_________/ \/ \__________________/ \/
 ID    #01   QCn   ANc   NSc   ARC   4     test     2    tld    0  Qtp   Qcl
```

### ?

```Python
    print "["+" ".join(format(ord(c), '02X') for c in self.data)+"]"
    print "ID:"+" ".join(format(ord(c), '02X') for c in self.data[0:2])
    print "FLAGS: "+" ".join(format(ord(c), '02X') for c in self.data[2:4])
    print "QueN: "+" ".join(format(ord(c), '02X') for c in self.data[4:6])
    print "AnsN: "+" ".join(format(ord(c), '02X') for c in self.data[6:8])
    print "NSN: "+" ".join(format(ord(c), '02X') for c in self.data[8:10])
    print "ARC: "+" ".join(format(ord(c), '02X') for c in self.data[10:12])
    print "ptr: "+" ".join(format(ord(c), '02X') for c in self.data[12:13])
    print "Qtp: "+" ".join(format(ord(c), '02X') for c in self.data[len(self.data)-4:len(self.data)-2])
```

