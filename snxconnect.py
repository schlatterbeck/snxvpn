#!/usr/bin/python

from __future__        import print_function, unicode_literals
import os
import os.path
import sys
import socket
import ssl
try :
    from urllib2 import build_opener, HTTPCookieProcessor, Request
    from urllib  import urlencode
    from httplib import IncompleteRead
    rsatype = long
except ImportError :
    from urllib.request import build_opener, HTTPCookieProcessor, Request
    from urllib.parse   import urlencode
    from http.client    import IncompleteRead
    rsatype = int
try :
    from cookielib import LWPCookieJar
except ImportError :
    from http.cookiejar import LWPCookieJar
from bs4               import BeautifulSoup
from getpass           import getpass
from argparse          import ArgumentParser
from netrc             import netrc, NetrcParseError
from Crypto.PublicKey  import RSA
from struct            import pack, unpack
from subprocess        import Popen, PIPE
from snxvpnversion     import VERSION

""" Todo:
    - timeout can be retrieved at /sslvpn/Portal/LoggedIn
      Function to do this is RetrieveTimeoutVal (url_above) in portal
      This seems to be in seconds. But my portal always displays
      "nNextTimeout = 6;" content-type is text/javascript.
    - We may want to get the RSA parameters from the javascript in the
      received html, RSA pubkey will probably be different for different
      deployments.
    - Log debug logs to syslog
"""

if sys.version_info >= (3,) :
    def b_ord (x) :
        return x
else :
    def b_ord (x) :
        return ord (x)

def iterbytes (x) :
    """ Compatibility with python3: Iterating over bytes returns int.
        Adding insult to injury calling bytes (23) will return a bytes
        object with length 23 filled with b'\0'. So we do this.
        Note that we will have to flatten iterators like the one
        resulting from a call to reversed.
    >>> a = []
    >>> for k in iterbytes (b'abcdef') :
    ...     a.append (k)
    >>> for k in iterbytes (reversed (b'abcdef')) :
    ...     a.append (k)
    >>> print (repr (b''.join (a)).lstrip ('b'))
    'abcdeffedcba'
    """
    if sys.version_info >= (3,) :
        x = bytes (x)
    else :
        x = b''.join (x)
    for i in range (len (x)) :
        yield (x [i:i+1])
# end def iterbytes

class HTML_Requester (object) :

    def __init__ (self, args) :
        self.modulus     = None
        self.exponent    = None
        self.args        = args
        self.jar         = j = LWPCookieJar ()

        if self.args.skip_cert:
            try:
                _create_unverified_https_context = ssl._create_unverified_context
            except AttributeError:
                # Legacy Python that doesn't verify HTTPS certificates by default
                pass
            else:
                # Handle target environment that doesn't support HTTPS verification
                ssl._create_default_https_context = _create_unverified_https_context

        self.has_cookies = False
        if self.args.cookiefile :
            self.has_cookies = True
            try :
                j.load (self.args.cookiefile, ignore_discard = True)
            except IOError :
                self.has_cookies = False
        self.opener   = build_opener (HTTPCookieProcessor (j))
        self.nextfile = args.file

    # end def __init__

    def call_snx (self) :
        """ The snx binary usually lives in the default snxpath and is
            setuid root. We call it with the undocumented '-Z' option.
            When everything is well it forks a subprocess and exists
            (daemonize). If an error occurs before forking we get the
            result back on one of the file descriptors. If everything
            goes well, the forked snx process opens a port on
            localhost:7776 (I've found no way this can be configured)
            and waits for us to pass the binary-encoded parameters via
            this socket. It later sends back an answer. It seems to keep
            the socket open, so we do another read to wait for snx to
            terminate.
        """
        sp  = self.args.snxpath
        snx = Popen ([sp, '-Z'], stdin = PIPE, stdout = PIPE, stderr = PIPE)
        stdout, stderr = snx.communicate ('')
        rc = snx.returncode
        if rc != 0 :
            print ("SNX terminated with error: %d %s%s" % (rc, stdout, stderr))
        sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        sock.connect (("127.0.0.1", 7776))
        sock.sendall (self.snx_info)
        answer = sock.recv (4096)
        if self.args.debug :
            f = open ('snxanswer', 'wb')
            f.write (answer)
            f.close ()
        print ("SNX connected, to leave VPN open, leave this running!")
        answer = sock.recv (4096) # should block until snx dies
    # end def call_snx

    def debug (self, s) :
        if self.args.debug :
            print (s)
    # end def debug

    def generate_snx_info (self) :
        """ Communication with SNX (originally by the java framework) is
            done via an undocumented binary format. We try to reproduce
            this here. We asume native byte-order but we don't know if
            snx binaries exist for other architectures with a different
            byte-order.
        """
        magic  = b'\x13\x11\x00\x00'
        length = 0x3d0
        gw_ip  = socket.gethostbyname(self.extender_vars ['host_name'])
        gw_int = unpack("!I", socket.inet_aton(gw_ip))[0]
        fmt    = b'=4sLL64sL6s256s256s128s256sH'
        info   = pack \
            ( fmt
            , magic
            , length
            , gw_int
            , self.extender_vars ['host_name']
            , int (self.extender_vars ['port'])
            , b''
            , self.extender_vars ['server_cn']
            , self.extender_vars ['user_name']
            , self.extender_vars ['password']
            , self.extender_vars ['server_fingerprint']
            , 1 # ???
            )
        assert len (info) == length + 8 # magic + length
        self.snx_info = info
    # end def generate_snx_info

    def login (self) :
        if self.has_cookies :
            self.debug ("has cookie")
            self.nextfile = 'Portal/Main'
            self.open ()
            self.debug (self.purl)
            if self.purl.endswith ('Portal/Main') :
                self.open ('sslvpn/SNX/extender')
                self.parse_extender ()
                self.generate_snx_info ()
                return True
            else :
                # Forget Cookies, otherwise we get a 400 bad request later
                self.jar.clear ()
                self.next_file (self.purl)
        self.debug (self.nextfile)
        self.open ()
        self.debug (self.purl)
        # Get the RSA parameters from the javascript in the received html
        for script in self.soup.find_all ('script') :
            if 'RSA' in script.attrs.get ('src', '') :
                self.next_file (script ['src'])
                self.debug (self.nextfile)
                break
        else :
            print ('No RSA javascript file found, cannot login')
            return
        self.open (do_soup = False)
        self.parse_rsa_params ()
        if not self.modulus :
            # Error message already given in parse_rsa_params
            return
        for form in self.soup.find_all ('form') :
            if 'id' in form.attrs and form ['id'] == 'loginForm' :
                self.next_file (form ['action'])
                assert form ['method'] == 'post'
                break
        self.debug (self.nextfile)

        enc = PW_Encode (modulus = self.modulus, exponent = self.exponent)
        d = dict \
            ( password      = enc.encrypt (self.args.password)
            , userName      = self.args.username
            , selectedRealm = self.args.realm
            , loginType     = self.args.login_type
            , vpid_prefix   = self.args.vpid_prefix
            , HeightData    = self.args.height_data
            )
        self.open (data = urlencode (d))
        self.debug (self.purl)
        self.debug (self.info)
        
        if self.args.multi_challenge :
            while 'MultiChallenge' in self.purl :
                d = self.parse_pw_response ()
                otp = getpass ('One-time Password: ')
                d ['password'] = enc.encrypt (otp)
                self.debug ("nextfile: %s" % self.nextfile)
                self.debug ("purl: %s" % self.purl)
                self.open (data = urlencode (d))
                self.debug ("info: %s" % self.info)

        if self.purl.endswith ('Login/ActivateLogin') :
            if self.args.save_cookies :
                self.jar.save (self.args.cookiefile, ignore_discard = True)
            self.debug ("purl: %s" % self.purl)
            self.open('sslvpn/Login/ActivateLogin?ActivateLogin=activate&LangSelect=en_US&submit=Continue&HeightData=')

        if self.purl.endswith ('Portal/Main') :
            if self.args.save_cookies :
                self.jar.save (self.args.cookiefile, ignore_discard = True)
            self.debug ("purl: %s" % self.purl)
            self.open  ('sslvpn/SNX/extender')
            self.debug (self.purl)
            self.debug (self.info)
            self.parse_extender ()
            self.generate_snx_info ()
            return True
        else :
            print ("Unexpected response, try again.")
            self.debug ("purl: %s" % self.purl)
            return
    # end def login

    def next_file (self, fname) :
        if fname.startswith ('/') :
            self.nextfile = fname.lstrip ('/')
        elif fname.startswith ('http') :
            self.nextfile = fname.split ('/', 3)[-1]
        else :
            dir = self.nextfile.split ('/')
            dir = dir [:-1]
            fn  = fname.split ('/')
            self.nextfile = '/'.join (dir + fn)
            # We might try to remove '..' elements in the future
    # end def next_file

    def open (self, filepart = None, data = None, do_soup = True) :
        filepart = filepart or self.nextfile
        url = '/'.join (('%s:/' % self.args.protocol, self.args.host, filepart))
        if data :
            data = data.encode ('ascii')
        rq = Request (url, data)
        self.f = f = self.opener.open (rq, timeout = 10)
        if do_soup :
            # Sometimes we get incomplete read. So we read everything
            # the server sent us and hope this is ok. Note: This means
            # we cannot pass the file to BeautifulSoup but need to read
            # everything here.
            try:
                page = f.read ()
            except IncompleteRead as e:
                page = e.partial
            self.soup = BeautifulSoup (page, "lxml")
        self.purl = f.geturl ()
        self.info = f.info ()
    # end def open

    def parse_extender (self) :
        """ The SNX extender page contains the necessary credentials for
            connecting the VPN. This information then passed to the snx
            program via a socket.
        """
        for script in self.soup.find_all ('script') :
            if '/* Extender.user_name' in script.text :
                break
        else :
            print ("Error retrieving extender variables")
            return
        for line in script.text.split ('\n') :
            if '/* Extender.user_name' in line :
                break
        stmts = line.split (';')
        vars  = {}
        for stmt in stmts :
            try :
                lhs, rhs = stmt.split ('=')
            except ValueError :
                break
            try :
                lhs = lhs.split ('.', 1)[1].strip ()
            except IndexError :
                continue
            rhs = rhs.strip ().strip ('"')
            vars [lhs] = rhs.encode ('utf-8')
        self.extender_vars = vars
    # end def parse_extender

    def parse_pw_response (self) :
        """ The password response contains another form where the
            one-time password (in our case received via a message to the
            phone) must be entered.
        """
        for form in self.soup.find_all ('form') :
            if 'name' in form.attrs and form ['name'] == 'MCForm' :
                self.next_file (form ['action'])
                assert form ['method'] == 'post'
                break
        d = {}
        for input in form.find_all ('input') :
            if input.attrs.get ('type') == 'password' :
                continue
            if 'name' not in input.attrs :
                continue
            if input ['name'] in ('password', 'btnCancel') :
                continue
            d [input ['name']] = input.attrs.get ('value', '')
        return d
    # end def parse_pw_response

    def parse_rsa_params (self) :
        keys = ('modulus', 'exponent')
        vars = {}
        for line in self.f :
            line = line.decode ('utf-8')
            for k in keys :
                if 'var %s' % k in line :
                    val = line.strip ().rstrip (';')
                    val = val.split ('=', 1) [-1]
                    val = val.strip ().strip ("'")
                    vars [k] = val
                    break
            if len (vars) == 2 :
                break
        else :
            print ('No RSA parameters found, cannot login')
            return
        self.debug (repr (vars))
        self.modulus  = rsatype (vars ['modulus'],  16)
        self.exponent = rsatype (vars ['exponent'], 16)
    # end def parse_rsa_params

# end class HTML_Requester

class PW_Encode (object) :
    """ RSA encryption module with special padding and reversing to be
        compatible with checkpoints implementation.
        Test with non-random padding to get known value:
        >>> p = PW_Encode (testing = True)
        >>> print (p.encrypt ('xyzzy'))
        451c2d5b491ee22d6f7cdc5a20f320914668f8e01337625dfb7e0917b16750cfbafe38bfcb68824b30d5cc558fa1c6d542ff12ac8e1085b7a9040f624ab39f625cabd77d1d024c111e42fede782e089400d2c9b1d6987c0005698178222e8500243f12762bebba841eae331d17b290f80bca6c3f8a49522fb926646c24db3627
        >>> print (p.encrypt ('XYZZYxyzzyXYZZYxyzzy'))
        a529e86cf80dd131e3bdae1f6dbab76f67f674e42041dde801ebdb790ab0637d56cc82f52587f2d4d34d26c490eee3a1ebfd80df18ec41c4440370b1ecb2dec3f811e09d2248635dd8aab60a97293ec0315a70bf024b33e8a8a02582fbabc98dd72d913530151e78b47119924f45b711b9a1189d5eec5a20e6f9bc1d44bfd554
    """

    def __init__ (self, modulus = None, exponent = None, testing = False) :
        m = rsatype \
            ( b'c87e9e96ffde3ec47c3f116ea5ac0e15'
              b'34490b3da6dbbedae1af50dc32bf1012'
              b'bdb7e1ff67237e0302b48c8731f343ff'
              b'644662de2bb21d2b033127660e525d58'
              b'889f8f6f05744906dddc8f4b85e0916b'
              b'5d9cf5b87093ed260238674f143801b7'
              b'e58a18795adc9acefaf0f378326fea19'
              b'9ac6e5a88be83a52d4a77b3bba5f1aed'
            , 16
            )
        e = rsatype (b'010001', 16)
        m = modulus  or m
        e = exponent or e
        self.pubkey  = RSA.construct ((m, e))
        self.testing = testing
    # end def __init__

    def pad (self, txt) :
        l = (self.pubkey.size () + 7) >> 3
        r = []
        r.append (b'\0')
        # Note that first reversing and then encoding to utf-8 would
        # *not* be correct!
        for x in iterbytes (reversed (txt.encode ('utf-8'))) :
            r.append (x)
        r.append (b'\0')
        n = l - len (r) - 2
        if self.testing :
            r.append (b'\1' * n)
        else :
            r.append (os.urandom (n))
        r.append (b'\x02')
        r.append (b'\x00')
        return b''.join (reversed (r))
    # end def pad

    def encrypt (self, password) :
        x = self.pad (password)
        e = self.pubkey.encrypt (x, '')[0]
        e = ''.join ('%02x' % b_ord (c) for c in reversed (e))
        return e
    # end def encrypt

# end class PW_Encode

def main () :
    # First try to parse config-file ~/.snxvpnrc:
    home = os.environ.get ('HOME')
    cfgf = None
    if home :
        try :
            cfgf = open (os.path.join (home, '.snxvpnrc'), 'rb')
        except (OSError, IOError) :
            pass
    cfg = {}
    boolopts = ['debug', 'save_cookies', 'multi_challenge', 'skip_cert']
    if cfgf :
        for line in cfgf :
            line = line.strip ().decode ('utf-8')
            if line.startswith ('#') :
                continue
            k, v = line.split (None, 1)
            if k == 'server' :
                k = 'host'
            k = k.replace ('-', '_')
            if k in boolopts :
                v = (v.lower () in ('true', 'yes'))
            cfg [k] = v

    host       = cfg.get ('host', '')
    cookiefile = cfg.get ('cookiefile', '%s/.snxcookies' % home)
    cmd = ArgumentParser ()
    cmd.add_argument \
        ( '-c', '--cookiefile'
        , help    = 'Specify cookiefile to save and attempt reconnect'
                    ' default="%(default)s"'
        , default = cookiefile
        )
    cmd.add_argument \
        ( '-D', '--debug'
        , help    = 'Debug handshake'
        , action  = 'store_true'
        , default = cfg.get ('debug', None)
        )
    cmd.add_argument \
        ( '-F', '--file'
        , help    = 'File part of URL default="%(default)s"'
        , default = cfg.get ('file', 'sslvpn/Login/Login')
        )
    cmd.add_argument \
        ( '-H', '--host'
        , help     = 'Host part of URL default="%(default)s"'
        , default  = host
        , required = not host
        )
    cmd.add_argument \
        ( '--height-data'
        , help    = 'Height data in form, default "%(default)s"'
        , default = cfg.get ('height_data', '')
        )
    cmd.add_argument \
        ( '-L', '--login-type'
        , help    = 'Login type, default="%(default)s"'
        , default = cfg.get ('login_type', 'Standard')
        )
    cmd.add_argument \
        ( '-MC', '--multi-challenge'
        , help    = 'MultiChallenge, default="%(default)s"'
        , default = cfg.get ('multi_challenge', False)
        )
    cmd.add_argument \
        ( '-P', '--password'
        , help    = 'Login password, not a good idea to specify on commandline'
        , default = cfg.get ('password', None)
        )
    cmd.add_argument \
        ( '-p', '--protocol'
        , help    = 'http or https, should *always* be https except for tests'
        , default = cfg.get ('protocol', 'https')
        )
    cmd.add_argument \
        ( '-R', '--realm'
        , help    = 'Selected realm, default="%(default)s"'
        , default = cfg.get ('realm', 'ssl_vpn')
        )
    cmd.add_argument \
        ( '-s', '--save-cookies'
        , help    = 'Save cookies to %(cookiefile)s, might be a security risk,'
                    ' default is off' % locals ()
        , action  = 'store_true'
        , default = cfg.get ('save_cookies', False)
        )
    cmd.add_argument \
        ( '-S', '--snxpath'
        , help    = 'snx binary to call, default="%(default)s", you might'
                    ' want a full path here'
        , default = cfg.get ('snxpath', 'snx')
        )
    cmd.add_argument \
        ( '-U', '--username'
        , help    = 'Login username, default="%(default)s"'
        , default = cfg.get ('username', '')
        )
    cmd.add_argument \
        ( '-V', '--vpid-prefix'
        , help    = 'VPID prefix, default "%(default)s"'
        , default = cfg.get ('vpid_prefix', '')
        )
    cmd.add_argument \
        ( '--version'
        , help    = 'Display version and exit'
        , action  = 'store_true'
        )
    cmd.add_argument \
        ( '-SC', '--skip-cert'
        , help    = 'Skip certificate verification'
        , action='store_true'
        )

    args = cmd.parse_args ()
    if args.version :
        print ("snxconnect version %s by Ralf Schlatterbeck" % VERSION)
        sys.exit (0)
    if not args.username or not args.password :
        n = a = None
        try :
            n = netrc ()
        except (IOError, NetrcParseError) :
            pass
        if n :
            a = n.authenticators (args.host)
        if a :
            un, dummy, pw = a
            if not args.username :
                args.username = un
            if not args.password :
                args.password = pw
        if not args.password :
            args.password = getpass ('Password: ')
    rq = HTML_Requester (args)
    result = rq.login ()
    if result :
        rq.call_snx ()
# end def main ()

if __name__ == '__main__' :
    main ()
