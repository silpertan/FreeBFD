#!/usr/bin/env python
#
# Simple Contrl client implementation for FreeBFD extension.
#

import os
import sys
import socket
import select
import json
import cmd

CTRL_ADDR = ('localhost', 5643)

READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR

class Commander(cmd.Cmd):
    def __init__(self, sock):
        cmd.Cmd.__init__(self, stdout=sys.stdout)
        self.sock = sock

    def do_quit(self, line):
        '''Quit the monitor.
        '''
        return True

    def do_raw(self, line):
        '''Send raw ascii line to server.

        Does not json encode the data.
        '''
        self.sock.sendall(line)

    def do_subscribe(self, line):
        '''Subscribe to a session.

        Argument can be '<session_id>' or 'all'.
        '''
        sess_id = line.split()[0]
        cmd = {
            'cmd': 'subscribe',
            'session' : sess_id,
        }
        self.sock.sendall(json.dumps(cmd))

    def do_unsubscribe(self, line):
        '''Unsubscribe from a session.

        Argument can be '<session_id>' or 'all'.
        '''
        sess_id = line.split()[0]
        cmd = {
            'cmd': 'unsubscribe',
            'session' : sess_id,
        }
        self.sock.sendall(json.dumps(cmd))


def main():
    poller = select.poll()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sys.stderr.write('connecting to %s\n' % str(CTRL_ADDR))
    try:
        sock.connect(CTRL_ADDR)
    except socket.error as msg:
        sys.stderr.write('%s\n' % msg)
        sys.exit(1)

    cmdr = Commander(sock)

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
                        if data.strip():
                            sys.stderr.write('RECV: "%s"\n' % data)
                        else:
                            sys.stderr.write('Monitor Server closed connection.\n')
                            isRunning = False
                            break

                    if s is sys.stdin:
                        count += 1
                        data = sys.stdin.readline().strip()
                        if data:
                            if cmdr.onecmd(data):
                                isRunning = False
                                break

    finally:
        sys.stderr.write('closing socket\n')
        sock.close()

if __name__ == '__main__':
    main()
