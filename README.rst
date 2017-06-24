=======
SNX-VPN
=======

By Ralf Schlatterbeck

This is a project to connect to a Checkpoint SSL-VPN from a Linux
client. The current version of checkpoint SNX (SSL Network Extender) for
Linux no longer supports a command-line mode. The supported version
involves a Browser with Java and is heavily dependent on the correct
Java version and other configuration options in the Browser. Moreover it
seems to only work with the Mozilla browsers (Firefox) not with others
like Chrome. Last not least Java and the Browser like to die frequently.

The current Checkpoint solution still depends on a command-line utility
called ``snx`` that needs root privileges and is installed either via
automatic download (and install) from Java or by hand. The web-page for
the SSL-VPN usually supports download of the correct snx-version for
that endpoint for manual installation.

In the new solution the ``snx`` binary is called with the undocumented
``-Z`` Option. In that mode it does not do the password negotiation
(which is done via the browser) but is only used for setting up the VPN
connection.

This project is an attempt to duplicate the Browser-based login with a
standalone program (in python) to get rid of all the Java version and
Browser intergration headache. We still rely on the ``snx`` binary by
Checkpoint which is called with the undocumented ``-Z`` option.

So far this is working for me with a Checkpoint SSL that uses username
and password authentication and in addition a one-time password
transmitted via SMS to the telephone of the person trying to connect.
If you're using certificate-based login or other methods, this will
probably not work for you out-of-the-box but you may want to help me
make it work.

Install and Run
---------------

The program should be installable with normal::

 python setup.py install --prefix=/usr/local

when you have already downloaded and unpacked the sources. Alternatively
install via ``pip`` should also work (replace ``pip`` with ``pip3`` if
you want to install for python3)::

 pip install snxvpn

The following dependencies are needed but should be picked up
automagically if you install via ``pip``:

- Beautiful Soup version 4 (``python-bs4`` Debian package)
- pycrypto (``python-crypto`` Debian package)

After installation you should be able to run ``snxconnect --help`` to
find out about options. At least a host, and username must be given,
either on the command-line via options or in a config file (see below).

The ``snxconnect`` program will currently create two files in the
current working directory where the program is started:

- ``snxanswer``: The not-yet-reverse-engineered answer of Checkpoint's
  ``snx`` program to the caller, only created if the ``--debug`` option
  is given
- ``cookies.txt``: The cookies from the remote end in the format known
  from the perl LWP library (available in python as LWPCookieJar), this
  is only created if the ``--save-cookies`` option is given.

The cookies might be used in a future version to reconnect if the
connection dies prematurely. And, yes, it might be a security risk to
save this to disk. Note that the cookies of course only have a limited
lifetime and your connection isn't very secure if you cannot be sure of
the files on your disk. Moreover all users of the current machine can
access the VPN connection anyway.

When you run Checkpoints ``snx`` for the first time with my program it
creates an X-Windows popup that lets you confirm the server fingerprint.
I've not seen this popup with the Java framework (but Java died several
times during my first experiments which is one of the reasons I wrote
this program, so that might be the reason I hadn't seen the popup
before).  You have to confirm this popup. The server fingerprint is
stored into a file with extension ``.db`` in ``/etc/snx``.

For configuration, ``snxconnect`` accepts a config file
``$HOME/.snxvpnrc``. The options there are the command-line long options
(obtained with --help) where a '-' is replaced with '_'.  For
compatibility with ``.snxrc``, the keyword ``server`` is an alias for
``host``. You can see which options were picked up from the config-file
by specifying ``--help``, where defaults are displayed, the defaults
from the config-file are displayed. Command-line options take precedence
over config-file entries.

In addition a ``.netrc`` file is supported that can contain username and
password by host name. Note that storing long-term login credentials on
disk is a security risk. See the manual page for ``netrc`` for further
details.

Notes on ``snx`` Installation
-----------------------------

From many posts on various mailinglists and forums, it is clear that
installing ``snx`` isn't straightforward. You need some non-standard
libraries installed that ``snx`` needs to function. Moreover ``snx`` is
a binary for the ``i386`` architecture, not a modern 64-bit AMD/Intel
architecture. I can only give hints for Debian installation here but the
general steps will apply to other distributions, too.

First of all if you're on a 64-bit architecture (called ``amd-64`` at
least by Debian) you need to enable multi-architecture support with::

  dpkg --add-architecture i386
  apt-get update

Then you need to install some packages that contain libraries needed by
``snx``, notably:

- ``libstdc++5:i386``
- ``libxcb1:i386``
- ``libaudit1:i386``
- ``libgcc1:i386``
- ``libxau6:i386``
- ``libxdmcp6:i386``

To check if you have all necessary libraries, you can run ``ldd`` on the
``snx`` binary (with sudo to root)::

 sudo ldd /usr/local/bin/snx

This should list a library file for each line and should not report any
missing libraries.

Some Notes on the Mechanisms
----------------------------

This section discusses some of the internals of how the ``snx`` program
is called by the Java framework and this program.

The Login process via the browser is a standard login page with lots of
Javascript and redirects. Passwords are sent in encrypted form to the
VPN gateway. The encryption uses a 2048 bit RSA key and pads the
password with random data before encryption (this is *good*). During
login the browser (or this program) picks up a lot of cookies and can
access necessary login information via Javascript. This information
includes:

- RSA public key for the password encryption
- Username to be passed to ``snx``
- A one-time password (different from the one received via telephone) to
  be passed to ``snx``
- Host name for TLS connection
- Port for TLS connection
- A server fingerprint

All these (except the RSA key) are passed to the ``snx`` program for
establishing the connection. The connection might use PPP internally as
some of the error messages (which are sent as part of the i18n info in
Javascript and map the error codes of ``snx`` to human-readable
messages) suggest.

If you call ``snx`` with the undocumented ``-Z`` option by hand, it
will terminate immediately. It obviously has other checks in place if it
is called "correctly".  To call ``snx`` correctly with this option,
``snx`` expects that standard input, output and error are UNIX pipes.
Only if something goes wrong and ``snx`` dies with an error-message,
these pipes are ever used. After startup, ``snx`` checks the existence
of a logfile and creates it if it doesn't exist or is not locked by
another ``snx`` process. Then it creates some other lockfiles in
``/etc/snx/tmp`` and then immediately forks a child process and lets the
parent process terminate. This forking and terminating sends the child
process to the background. The first step the child process does is
close the file-descriptors for standard input, output, and error.

After this, ``snx`` opens and listens on a TCP socket on port 7776 on
the local machine. I haven't found options for telling ``snx`` to use
another port. The calling application (e.g., this program or the
original Java framework) is expected to pass the connection information
detailed above in an undocumented binary format. After that ``snx``
establishes a VPN connection and reports back with another blob of
binary information on the same socket. The socket must then be kept open
by the calling application, otherwise ``snx`` terminates. It may well be
that ``snx`` accepts further commands on that socket, e.g., for renewing
the authentication after the VPN timeout has expired. We log the binary
data received on that socket to the file ``snxanswer`` if debugging is
enabled.
