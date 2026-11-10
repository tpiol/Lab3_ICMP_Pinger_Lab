from socket import *  # gives me all the socket stuff so I can send and receive packets
import os  # lets me get my program's process ID (used as the ping ID)
import sys  # lets me check what computer I'm on (Mac vs. Windows/Linux)
import struct  # turns numbers into raw bytes and back again
import time  # lets me get the current time so I can measure RTT
import select  # lets me wait for a packet without freezing forever
import binascii  # converts binary to readable stuff (not actually used, it came with the skeleton)

ICMP_ECHO_REQUEST = 8  # type 8 = echo request, same as the ping request I saw in Wireshark

def checksum(string):  # calculates the ICMP checksum so the receiver knows nothing got messed up
    csum = 0  # start the running total at 0
    countTo = (len(string) // 2) * 2  # round the length down to an even number since we add 2 bytes at a time
    count = 0  # start at the first byte

    while count < countTo:  # go through the bytes 2 at a time
        thisVal = (string[count + 1]) * 256 + (string[count])  # combine 2 bytes into one 16-bit number
        csum += thisVal  # add it to the total
        csum &= 0xffffffff  # keep the total from getting bigger than 32 bits
        count += 2  # move to the next pair of bytes

    if countTo < len(string):  # if there's one leftover byte (odd length)
        csum += (string[len(string) - 1])  # add that last byte too
        csum &= 0xffffffff  # keep it within 32 bits again

    csum = (csum >> 16) + (csum & 0xffff)  # fold the top 16 bits into the bottom 16 bits
    csum = csum + (csum >> 16)  # fold again in case there was a carry
    answer = ~csum  # flip all the bits (that's how the internet checksum works)
    answer = answer & 0xffff  # keep only 16 bits
    answer = answer >> 8 | (answer << 8 & 0xff00)  # swap the two bytes so they're in the right order
    return answer  # give back the finished checksum

def receiveOnePing(mySocket, ID, timeout, destAddr):  # waits for the reply to my ping and reads it
    timeLeft = timeout  # how much time I have left to wait (starts at 1 second)

    while 1:  # keep looping until I get my reply or run out of time
        startedSelect = time.time()  # write down the time before I start waiting
        whatReady = select.select([mySocket], [], [], timeLeft)  # wait until a packet shows up or time runs out
        howLongInSelect = (time.time() - startedSelect)  # figure out how long I just waited
        if whatReady[0] == []: # Timeout  # nothing showed up in time
            return (None, None)  # so give back nothing (counts as a lost ping)

        timeReceived = time.time()  # write down the exact time the reply came in
        recPacket, addr = mySocket.recvfrom(1024)  # grab the packet (up to 1024 bytes) and who sent it

        #Fill in start
        #Fetch the ICMP header from the IP packet
        icmpHeader = recPacket[20:28]  # skip the 20-byte IP header and grab the 8-byte ICMP header
        icmpType, code, icmpChecksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)  # turn those 8 bytes back into type, code, checksum, ID, sequence

        if icmpType == 0 and packetID == ID:  # only keep it if it's an echo reply (type 0) AND it's a reply to MY ping
            timeSent = struct.unpack("d", recPacket[28:36])[0]  # read the send time that sendOnePing hid in the data (8 bytes after the header)
            delay = (timeReceived - timeSent) * 1000  # RTT = time received minus time sent, times 1000 to get milliseconds
            return (delay, (icmpType, code, icmpChecksum, packetID, sequence, timeSent))  # give back the delay and all the ICMP fields like Gradescope wants
        #Fill in end

        timeLeft = timeLeft - howLongInSelect  # subtract the time I already waited
        if timeLeft <= 0:  # if I'm out of time
            return (None, None)  # give up on this ping (counts as lost)

def sendOnePing(mySocket, destAddr, ID):  # builds the ping packet and sends it
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0  # start with a fake checksum of 0 since we can't calculate it yet
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)  # pack type 8, code 0, checksum 0, my ID, sequence 1 into 8 bytes
    data = struct.pack("d", time.time())  # put the current time in the data so I can calculate RTT later

    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)  # now calculate the real checksum over the header and data

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':  # if I'm on a Mac
        # Convert 16-bit integers from host to network byte order
        myChecksum = htons(myChecksum) & 0xffff  # flip it to network byte order and keep it 16 bits
    else:  # if I'm on Windows or Linux
        myChecksum = htons(myChecksum)  # just flip it to network byte order

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)  # rebuild the header, this time with the real checksum
    packet = header + data  # stick the header and data together to make the full ICMP packet
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str  # send it to the destination (the 1 doesn't matter since ICMP has no ports)

    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.

def doOnePing(destAddr, timeout):  # does one full ping: open socket, send, receive, close
    icmp = getprotobyname("icmp")  # get ICMP's protocol number (it's 1, same as Wireshark showed)

    # SOCK_RAW is a powerful socket type. For more details: http://sock-raw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)  # make a raw socket so I can build my own ICMP packets (this is why I need sudo)

    myID = os.getpid() & 0xFFFF # Return the current process i  # use my program's process ID as the ping ID, cut down to 16 bits
    sendOnePing(mySocket, destAddr, myID)  # send the ping
    result = receiveOnePing(mySocket, myID, timeout, destAddr)  # wait for the reply and read it
    mySocket.close()  # close the socket since I'm done with it
    return result  # give back the delay and ICMP fields (or None, None if it timed out)

def ping(host, timeout=1):  # the main ping function that Gradescope tests
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)  # turn a website name into an IP address (like DNS)
    resps = []  # empty list to save all my ping results
    print("Pinging " + dest + " using Python:")  # print which IP I'm pinging
    print("")  # print a blank line so it looks nice

    # Calculate vars values and return them
    # Send ping requests to a server separated by approximately one second
    for i in range(0,5):  # send 5 pings total
        result = doOnePing(dest, timeout)  # do one ping and get the result
        resps.append(result)  # save the result in my list
        time.sleep(1) # one second  # wait 1 second before the next ping

    return resps  # give back the list of all 5 results

if __name__ == '__main__':  # only runs when I run this file myself (not when Gradescope imports it)
    print(ping("127.0.0.1"))  # ping my own computer first to test, then change this to a far-away site