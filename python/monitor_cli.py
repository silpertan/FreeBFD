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

class SessionID(object):
    def __init__(self, peer, local=None, peerPort=None, localPort=None):
        self.peer = peer
        self.local = local
        self.peerPort = peerPort
        self.localPort = localPort

    def to_port(self, port):
        try:
            p = int(port)
        except ValueError:
            p = 0

        if p < 0:
            p = 0
        if p > 0xFFFF:
            p = 0xFFFF

        return p

    def PeerPort(self):
        return self.to_port(self.peerPort)

    def LocalPort(self):
        return self.to_port(self.localPort)


class MonitorMsg(object):
    def __init__(self, msgtype, sess_id):
        self.msg = {
            'MsgType': msgtype,
            'SessionID' : {
                'PeerIP' : sess_id.peer
            }
        }

        if sess_id.local is not None:
            self.msg['SessionID']['LocalIP'] = sess_id.local

        if sess_id.peerPort is not None:
            self.msg['SessionID']['PeerPort'] = sess_id.PeerPort()

        if sess_id.localPort is not None:
            self.msg['SessionID']['LocalPort'] = sess_id.LocalPort()

    def to_json(self):
        return json.dumps(self.msg)

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

        Argument can be '<peer-ip> [<local-ip> [<peer-port> [<local-port>]]]'.
        '''
        argv = line.split()
        msg = MonitorMsg('Subscribe', SessionID(*argv))
        self.sock.sendall(msg.to_json())

    def do_unsubscribe(self, line):
        '''Unsubscribe from a session.

        Argument can be '<peer-ip> [<local-ip> [<peer-port> [<local-port>]]]'.
        '''
        argv = line.split()
        msg = MonitorMsg('Unsubscribe', SessionID(*argv))
        self.sock.sendall(msg.to_json())


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
