from socket import *  # gives me gethostbyname so I can turn a website name into an IP
import time  # lets me wait 1 second between pings
from client import doOnePing  # reuse my doOnePing from client.py so I don't rewrite everything

def ping(host, timeout=1):  # same ping as before, but it prints stats at the end like real ping
    dest = gethostbyname(host)  # turn the website name into an IP address
    print("Pinging " + dest + " using Python:")  # print which IP I'm pinging
    print("")  # blank line so it looks nice

    delays = []  # list to save the RTT of every ping that got a reply
    sent = 0  # counter for how many pings I sent

    for i in range(0, 5):  # send 5 pings
        sent += 1  # count this ping as sent
        delay, fields = doOnePing(dest, timeout)  # do one ping and get the delay and ICMP fields back
        if delay is None:  # if nothing came back in time
            print("Request timed out")  # tell the user this one was lost
        else:  # if I got a reply
            delays.append(delay)  # save the RTT so I can do stats later
            print("Reply from " + dest + ": seq=" + str(i) + " time=" + str(round(delay, 3)) + " ms")  # print the RTT like real ping does
        time.sleep(1)  # wait 1 second before the next ping

    received = len(delays)  # how many replies I actually got
    loss = (sent - received) / sent * 100  # packet loss % = lost pings divided by sent pings, times 100

    print("")  # blank line before the summary
    print("--- " + host + " ping statistics ---")  # header like real ping
    print(str(sent) + " packets transmitted, " + str(received) + " packets received, " + str(round(loss, 1)) + "% packet loss")  # show sent, received, and loss %

    if received > 0:  # only do min/avg/max if at least one reply came back (can't divide by 0)
        minRTT = min(delays)  # smallest RTT
        maxRTT = max(delays)  # biggest RTT
        avgRTT = sum(delays) / received  # average RTT = add them all up and divide by how many
        print("round-trip min/avg/max = " + str(round(minRTT, 3)) + "/" + str(round(avgRTT, 3)) + "/" + str(round(maxRTT, 3)) + " ms")  # print it like real ping

if __name__ == '__main__':  # only runs when I run this file myself
    ping("www.ust.hk")  # ping Hong Kong so the RTTs are big and interesting