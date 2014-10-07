#!/usr/bin/env python
#
# Simple Control server implementation for FreeBFD extension.
#

import os
import sys
import socket
import select
import Queue

from monitor_cli import CTRL_ADDR

READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
READ_WRITE = READ_ONLY | select.POLLOUT

TIMEOUT = 5000

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sys.stderr.write('starting up on %s\n' % str(CTRL_ADDR))
    sock.bind(CTRL_ADDR)

    sock.listen(5)

    fd_to_socket = {
        sock.fileno(): sock,
    }

    msg_queues = {}

    poller = select.poll()
    poller.register(sock, READ_ONLY)

    # Must be able to handle multiple control clients concurrently.
    while True:
        sys.stderr.write('waiting for next event\n')
        events = poller.poll(TIMEOUT)

        if not events:
            sys.stderr.write('TIMEOUT\n')
            for s,q in msg_queues.iteritems():
                poller.register(s, READ_WRITE)
                q.put('PING')

        for fd, flag in events:
            s = fd_to_socket[fd]

            if flag & (select.POLLIN | select.POLLPRI):

                if s is sock:
                    conn,cli_addr = s.accept()
                    sys.stderr.write('New Connection: %s\n' % str(cli_addr))
                    fd_to_socket[conn.fileno()] = conn
                    poller.register(conn, READ_ONLY)
                    msg_queues[conn] = Queue.Queue()
                else:
                    data = s.recv(256)
                    if data:
                        sys.stderr.write('RECV [%s]: (%d)"%s"\n' % (s.getpeername(),
                                                                    len(data), data))
                    else:
                        sys.stderr.write('closing %s after reading no data\n'
                                         % str(s.getpeername()))
                        del fd_to_socket[fd]
                        poller.unregister(s)
                        del msg_queues[s]
                        s.close()

            elif flag & select.POLLHUP:
                sys.stderr.write('closing %s after receiving HUP\n'
                                 % s.getpeername())
                del fd_to_socket[fd]
                poller.unregister(s)
                del msg_queues[s]
                s.close()

            elif flag & select.POLLERR:
                sys.stderr.write('handling exceptional condition for %s\n'
                                 % s.getpeername())
                del fd_to_socket[fd]
                poller.unregister(s)
                del msg_queues[s]
                s.close()

            elif flag & select.POLLOUT:
                try:
                    msg = msg_queues[s].get_nowait()
                except Queue.Empty:
                    poller.modify(s, READ_ONLY)
                else:
                    s.send(msg)

if __name__ == '__main__':
    main()
