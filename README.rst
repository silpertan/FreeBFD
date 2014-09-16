BFD (Bidirection Forwarding Detection)
======================================

This is an implementation of the BFD (Bidirectional Forwarding
Detection) protocol.

It consists of two processes:

**bfd**
    Runs just a single BFD session using parameters specified on the
    command line.

**bfdd**
    Can support multiple BFD sessions that are specified either
    statically in a config file or dynamically via a monitor socket; a
    library is provided for communicating with bfdd over the monitor
    socket to create sessions and receive session state change
    notifications.

Dependencies
------------

**libconfig**
    (http://www.hyperrealm.com/libconfig/)::

        $ apt-get install libconfig-dev
