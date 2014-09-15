#!/usr/bin/env python
#
# Simple Contrl client implementation for FreeBFD extension.
#

import os
import sys
import socket
import select

CTRL_ADDR = ('localhost', 5643)

READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR

def main():
    poller = select.poll()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sys.stderr.write('connecting to %s\n' % str(CTRL_ADDR))
    try:
        sock.connect(CTRL_ADDR)
    except socket.error as msg:
        sys.stderr.write('%s\n' % msg)
        sys.exit(1)

    try:
        isRunning = True
        count = 0

        fd_to_socket = {
            sock.fileno(): sock,
            sys.stdin.fileno(): sys.stdin,
        }

        poller.register(sock, READ_ONLY)
        poller.register(sys.stdin, READ_ONLY)

        while isRunning:
            sys.stderr.write('[%04d] >>> ' % count)
            events = poller.poll()

            for fd, flag in events:
                s = fd_to_socket[fd]

                if flag & (select.POLLIN | select.POLLPRI):
                    if s is sock:
                        data = sock.recv(256)
                        if data:
                            sys.stderr.write('RECV: "%s"\n' % data)
                        else:
                            isRunning = False
                            break

                    if s is sys.stdin:
                        count += 1
                        data = sys.stdin.readline()
                        if data and data.strip().lower() == 'quit':
                            isRunning = False
                            break
                        sock.sendall(data.strip())

    finally:
        sys.stderr.write('closing socket\n')
        sock.close()

if __name__ == '__main__':
    main()
