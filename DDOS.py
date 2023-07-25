import socket
import sys
import threading

ip = input("Enter ip (for localhost write localhost):")
port = int(input("Enter port:"))
msg = input("Enter message:")


class myThread(threading.Thread):

    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter

    def run(self):
        print ("Starting " + self.name)
        attack(ip, port, msg, self.threadID)
        print ("Exiting " + self.name)


def attack(ip, port, msg, thread_id):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect the socket to the port where the server is listening
    server_address = (ip, port)
    print(sys.stderr, 'connecting to %s port %s' % server_address)
    sock.connect(server_address)
    try:
        # Send data
        threadmsg='Thread-',thread_id,':',msg;
        message = str.encode(str(threadmsg))
        print(sys.stderr, 'thread-',thread_id, 'sending "%s"' % message)
        sock.sendall(message)
        # Look for the response
        amount_received = 0
        amount_expected = len(message)
        while amount_received < amount_expected:
            data = sock.recv(16)
            amount_received += len(data)
            print(sys.stderr, 'received "%s"' % data)
    finally:
        print(sys.stderr, 'closing socket')
        sock.close()


i = 0
# Create new threads
thread1 = myThread(1, "Thread-1", 1)
thread2 = myThread(2, "Thread-2", 2)
thread3 = myThread(3, "Thread-3", 3)
thread1.start()
thread2.start()
thread3.start()
while i < 10:
    # Start new Threads
    thread1.run()
    thread2.run()
    thread3.run()
    i=i+1
print("Exiting Main Thread")
