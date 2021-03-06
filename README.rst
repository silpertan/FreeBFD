=========
 FreeBFD
=========

This is an implementation of the BFD (Bidirectional Forwarding
Detection) protocol.

BFD is defined in `RFC5880 <http://tools.ietf.org/html/rfc5880>`_.

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

Status
------

The implemenation is still quite immature. It is able to bring up and
maintain a session with a Cisco router (and with another FreeBFD host),
but it has not been tested thoroughly. Also, many of the design ideas
are still being implemented (and documented).

Dependencies
------------

**libconfig** (http://www.hyperrealm.com/libconfig/)::

    $ apt-get install libconfig-dev

**json-c** (https://github.com/json-c/json-c/wiki)::

    $ apt-get install libjson-c-dev

Session Monitoring
------------------

Sessions can be monitored by external applications via TCP connections
to the monitor port (defaults to 5643) of the bfdd appication.

A monitor application connects to the monitor TCP server port and
issues session subscription commands to the **bfdd** daemon process.
Once subscribed, the **bfdd** daemon will send notifications to the
monitor application on session state transitions.

Multiple monitor applications can be connected to the **bfdd** daemon
simultaneously. Each monitor can subscribe to notifications for a
specific session or for all sessions.

Communication over the TCP connection consists of JSON encoded data
packets.

Subscribing to notificaions for a session will cause a session to be
created if it doesn't exists. Subscribing to notifications for a
session which already exists is perfectly acceptible.

Unsubscribing from notifications will cause a session to be destroyed
if the number of subscriptions to the session drops to zero.

Questions & Concerns
++++++++++++++++++++

* Does it make sense to destory sessions if there are no
  subscriptions? How would that work in the data center if nothing is
  subscribed to dynamically created sessions?

Monitor Commands
++++++++++++++++

These are sent from the monitor application to the **bfdd** daemon.

* Subscribe to session(s)::

    {
        "MsgType" : "Subscribe",
        "SessionID" : {
            "PeerAddr" : "<ip-addr>",
            "LocalAddr" : "<ip-addr>",
            "PeerPort" : <int>,   // Optional: Defaults to 3784
            "LocalPort" : <int>,  // Optional: Defaults to 3784
        },
        // The following are optional.
        "SessionOpts" : {
            "DemandMode" : "on|off",
            "DetectMult" : <int>,
            "AuthType" : <int>,        // TODO: No implemented yet
            "RequiredMinRxInterval" : <int>,
            "DesiredMinTxInterval" : <int>,
        }
    }

* Unsubscribe from session(s)::

    {
        "MsgType" : "Unsubscribe",
        "SessionID" : {
            "PeerAddr" : "<ip-addr>",
            "LocalAddr" : "<ip-addr>",
            "PeerPort" : <int>,   // Optional: Defaults to 3784
            "LocalPort" : <int>,  // Optional: Defaults to 3784
        }
    }

Monitor Notifications
+++++++++++++++++++++

These are sent from the **bfdd** daemon to the monitor applications.

* Session State::

    {
        "MsgType" : "Notify",
        "SessionID" : {
            "PeerAddr" : "<ip-addr>",
            "LocalAddr" : "<ip-addr>",
            "PeerPort" : <int>,   // Optional: Defaults to 3784
            "LocalPort" : <int>,  // Optional: Defaults to 3784
        },
        "State" : "AdminDown|Down|Init|Up"
    }
