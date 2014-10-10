======
 TODO
======

* Improve scalability of total number of socket actors (currently
  limited to < 20).
* Allow bind()ing a session to a specific local IP address (thus tying
  it to a specific network interface). If this is not done
  (i.e. binding to INADDR_ANY), will users be able to monitor the
  status of a specific physical connection?
* Dynamic session creation in BFD (mon subscribes to BFDD which
  connects to BFD causing BFD to create a session without the session
  being defined on the command line).

* BUG: Re-establishing session via subscription fails. Steps to repro:
    # Start bfdd with no sessions.
    # Start bfdmontest (which starts the session via subscription).
    # Start bfd (see that session is now up.
    # Kill bfdd (which also kills bfdmontest), but leave bfd running.
    # See session go to 'Down' in bfd instance.
    # Restart bfdd with no sessions.
    # Restart bfdmontest (should re-subscribe to session already in bfd).
  RESULTS:
    - bfdd loops with the following:
        bfdd[6356]: Can't find session for 1f5cc50 from 127.0.0.1:49144[d79420]
        bfdd[6356]: Can't find session for ctl pkt from 127.0.0.1:49144[d79420]
    - bfd loops with the following:
        bfd[6264]: [d79420] Bad state, zero yourDiscr in pkt from 127.0.0.1:49142[1fbdc50]
