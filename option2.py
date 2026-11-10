from socket import *  # all the socket stuff
import os  # for the process ID
import struct  # for unpacking bytes into numbers
import time  # for timing and sleeping
import select  # for waiting on the socket with a timeout
from client import sendOnePing  # reuse my sendOnePing from client.py

# what each ICMP error type/code means, so I can print it in plain English
ERRORS = {
    (3, 0): "Destination Network Unreachable",  # type 3 code 0
    (3, 1): "Destination Host Unreachable",  # type 3 code 1
    (3, 2): "Destination Protocol Unreachable",  # type 3 code 2
    (3, 3): "Destination Port Unreachable",  # type 3 code 3 (like my Wireshark extra credit)
    (3, 6): "Destination Network Unknown",  # type 3 code 6
    (3, 7): "Destination Host Unknown",  # type 3 code 7
    (11, 0): "TTL Expired in Transit",  # type 11 code 0 (like traceroute)
}

def receiveOnePing(mySocket, ID, timeout, destAddr):  # waits for a reply OR an error
    timeLeft = timeout  # start with the full timeout

    while 1:  # keep checking until I get something or run out of time
        startedSelect = time.time()  # time before waiting
        whatReady = select.select([mySocket], [], [], timeLeft)  # wait for a packet or the timeout
        howLongInSelect = (time.time() - startedSelect)  # how long I waited
        if whatReady[0] == []:  # nothing came back
            return (None, "Request timed out")  # report a timeout

        timeReceived = time.time()  # time the packet arrived
        recPacket, addr = mySocket.recvfrom(1024)  # grab the packet and who sent it

        icmpHeader = recPacket[20:28]  # skip the 20-byte IP header, grab the 8-byte ICMP header
        icmpType, code, icmpChecksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)  # unpack the fields

        if icmpType == 0 and code == 0 and packetID == ID:  # normal echo reply to MY ping
            timeSent = struct.unpack("d", recPacket[28:36])[0]  # read the send time from the data
            delay = (timeReceived - timeSent) * 1000  # RTT in milliseconds
            return (delay, None)  # good reply, no error

        if icmpType in (3, 11):  # it's an error message (destination unreachable or TTL exceeded)
            innerHeader = recPacket[48:56]  # the copy of MY original ICMP header inside the error
            innerType, innerCode, innerChecksum, innerID, innerSeq = struct.unpack("bbHHh", innerHeader)  # unpack my original header
            if innerID == ID:  # the error is about MY ping
                message = ERRORS.get((icmpType, code), "ICMP error type " + str(icmpType) + " code " + str(code))  # look up what it means
                return (None, message + " (from " + addr[0] + ")")  # report the error and which router sent it

        timeLeft = timeLeft - howLongInSelect  # subtract the time I already waited
        if timeLeft <= 0:  # out of time
            return (None, "Request timed out")  # report a timeout

def doOnePing(destAddr, timeout, ttl):  # one ping, but I can set the TTL
    icmp = getprotobyname("icmp")  # ICMP's protocol number (1)
    mySocket = socket(AF_INET, SOCK_RAW, icmp)  # raw socket (needs sudo)
    mySocket.setsockopt(IPPROTO_IP, IP_TTL, ttl)  # set the TTL so I can force a TTL exceeded error
    myID = os.getpid() & 0xFFFF  # my process ID as the ping ID
    try:  # sending can fail if the network is unreachable
        sendOnePing(mySocket, destAddr, myID)  # send the ping
    except OSError as e:  # my own computer refused to send it
        mySocket.close()  # close the socket
        return (None, "Send failed: " + str(e))  # report what went wrong
    result = receiveOnePing(mySocket, myID, timeout, destAddr)  # wait for a reply or error
    mySocket.close()  # done with the socket
    return result  # give back (delay, error)

def ping(host, timeout=1, ttl=64):  # ping that shows errors instead of just timing out
    dest = gethostbyname(host)  # website name to IP
    print("Pinging " + dest + " with TTL " + str(ttl) + " using Python:")  # show what I'm doing
    print("")  # blank line

    for i in range(0, 5):  # send 5 pings
        delay, error = doOnePing(dest, timeout, ttl)  # do one ping
        if error:  # something went wrong
            print(error)  # print the error in plain English
        else:  # it worked
            print("Reply from " + dest + ": time=" + str(round(delay, 3)) + " ms")  # print the RTT
        time.sleep(1)  # wait 1 second

if __name__ == '__main__':  # only runs when I run this file myself
    ping("www.ust.hk", ttl=1)  # TTL 1 makes my router send back TTL exceeded errors
    print("")  # blank line between tests
    ping("www.ust.hk")  # normal TTL so it works like regular ping