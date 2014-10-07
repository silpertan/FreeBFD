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
import optparse
import shlex
import threading
import time

CTRL_ADDR = ('localhost', 5643)

READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR

class SessionID(object):
    def __init__(self, peer, local=None):
        self.local = socket.inet_ntoa(socket.inet_aton('0'))
        self.peerPort = '0'
        self.localPort = '0'

        peer = peer.split(':', 1)
        self.peer = peer[0]
        if len(peer) > 1:
            self.peerPort = peer[1]

        if local is not None:
            local = local.split(':', 1)
            try:
                self.local = socket.inet_ntoa(socket.inet_aton(local[0]))
            except socket.error as e:
                sys.stderr.write('WARNING: %s: %s\n' % (str(e), local[0]))
            if len(local) > 1 and local[1]:
                self.localPort = local[1]

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
    def __init__(self, msgtype, sess_id, sess_opts=None):
        self.msg = {
            'MsgType': msgtype,
            'SessionID' : {
                'PeerAddr' : sess_id.peer
            }
        }

        if sess_id.local is not None:
            self.msg['SessionID']['LocalAddr'] = sess_id.local

        if sess_id.peerPort is not None:
            self.msg['SessionID']['PeerPort'] = sess_id.PeerPort()

        if sess_id.localPort is not None:
            self.msg['SessionID']['LocalPort'] = sess_id.LocalPort()

        if sess_opts:
            self.msg['SessionOpts'] = sess_opts

    def to_json(self):
        return json.dumps(self.msg)

class SubscribeOptParser(optparse.OptionParser):
    def __init__(self):
        optparse.OptionParser.__init__(self, add_help_option=False)
        self.add_option('-o', '--option', action='append', default=[])

    def error(self, msg):
        self.exit(msg=msg)

    def exit(self, status=0, msg=None):
        '''Replace parser exit() method so that it does not exit on errors.
        '''
        if msg:
            sys.stderr.write('%s\n' % msg)

class Commander(cmd.Cmd):
    SubscribeOpts = {
        'DemandMode': str,
        'DetectMult': int,
        'DesiredMinTxInterval': int,
        'RequiredMinRxInterval': int,
    }

    def __init__(self, sock):
        cmd.Cmd.__init__(self, stdout=sys.stdout)
        self.sock = sock
        self.cmd_cnt = 1
        self.prompt = '[%04d] >>> ' % self.cmd_cnt
        self.subscribe_parser = SubscribeOptParser()

    def emptyline(self):
        '''Overriding to avoid resending last cmd on empty line.
        '''
        pass

    def postcmd(self, stop, line):
        if line.strip():
            self.cmd_cnt += 1
            self.prompt = '[%04d] >>> ' % self.cmd_cnt
        return stop

    def send(self, data):
        try:
            self.sock.sendall(data)
        except socket.error as err:
            sys.stderr.write('%s\n' % str(err))

    def do_quit(self, line):
        '''Quit the monitor.
        '''
        return True

    def do_raw(self, line):
        '''Send raw ascii line to server.

        Does not json encode the data.
        '''
        self.send(line)

    def do_subscribe(self, line):
        '''Subscribe to a session.

        Argument can be:
          '<peer-addr>[:<peer-port>] [<local-addr>[:<local-port>]] [-o <key>=<val>]'

        Multiple options (-o) can be given. Valid keys follow:
            * DemandMode=on|off
            * DetectMult=<int>
            * DesiredMinTxInterval=<int>
            * RequiredMinRxInterval=<int>
        '''
        argv = shlex.split(line)
        opts,args = self.subscribe_parser.parse_args(argv)
        if args:
            errs = 0
            sess_opts = {}
            for o in opts.option:
                kv = o.split('=', 1)
                if len(kv) != 2:
                    sys.stderr.write('Badly formatted option: %s\n' % (o))
                    errs += 1
                    continue

                k,v = kv
                if k not in self.SubscribeOpts:
                    sys.stderr.write('Unknown option: %s\n' % (k))
                    errs += 1
                    continue

                conversion = self.SubscribeOpts[k]
                try:
                    sess_opts[k] = conversion(v)
                except ValueError as e:
                    sys.stderr.write('Failed to convert option: %s\n' % str(e))
                    errs += 1

            if not errs:
                msg = MonitorMsg('Subscribe', SessionID(*args), sess_opts)
                self.send(msg.to_json())
        else:
            sys.stderr.write("Missing required arguments.\n")

    def do_unsubscribe(self, line):
        '''Unsubscribe from a session.

        Argument can be '<peer-ip>[:<peer-port>] [<local-ip>[:<local-port>]]'.
        '''
        argv = shlex.split(line)
        if argv:
            msg = MonitorMsg('Unsubscribe', SessionID(*argv))
            self.send(msg.to_json())
        else:
            sys.stderr.write("Missing required arguments.\n")


class SocketReader(threading.Thread):
    def __init__(self, sock):
        threading.Thread.__init__(self)
        self.sock = sock
        self.isRunning = True
        self.socket_map = {
            self.sock.fileno(): sock,
        }

    def stop(self):
        sys.stderr.write('Stopping SocketReader\n')
        self.isRunning = False
        self.join(5)
        if self.isAlive():
            raise Exception('Failed to stop SocketReader thread.')

    def run(self):
        sys.stderr.write('Starting SocketReader\n')

        try:
            poller = select.poll()
            poller.register(self.sock, READ_ONLY)

            while self.isRunning:
                events = poller.poll(0.1)

                for fd, flag in events:
                    if flag & (select.POLLIN | select.POLLPRI):
                        s = self.socket_map[fd]

                        if s is self.sock:
                            data = self.sock.recv(256)
                            if not data:
                                sys.stderr.write('Monitor server closed connection.\n')
                                self.isRunning = False
                                break
                            sys.stderr.write('RECV: %s\n' % data.strip())
        finally:
            sys.stderr.write('closing socket\n')
            self.sock.close()


INTRO = '''
=======================
 Python Monitor Client
=======================

Type "help" for list of commands.
Type "help <cmd>" for help on command.

-----------------------
'''

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sys.stderr.write('connecting to %s\n' % str(CTRL_ADDR))
    try:
        sock.connect(CTRL_ADDR)
    except socket.error as msg:
        sys.stderr.write('%s\n' % msg)
        sys.exit(1)

    th = SocketReader(sock)
    th.start()

    try:
        time.sleep(0.2)
        cmdr = Commander(sock)
        cmdr.cmdloop(INTRO)
    finally:
        th.stop()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
