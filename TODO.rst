======
 TODO
======

* Design and implement monitor client library.
* Improve scalability of total number of socket actors (currently
  limited to < 20).
* Allow bind()ing a session to a specific local IP address (thus tying
  it to a specific network interface). If this is not done
  (i.e. binding to INADDR_ANY), will users be able to monitor the
  status of a specific physical connection?
* Dynamic session creation in BFD (mon subscribes to BFDD which
  connects to BFD causing BFD to create a session without the session
  being defined on the command line).
