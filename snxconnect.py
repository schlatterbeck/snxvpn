#!/usr/bin/python

import sys
import urllib2
from rsclib.HTML_Parse import Page_Tree
from cookielib         import CookieJar
from bs4               import BeautifulSoup
from getpass           import getpass
from urllib            import urlencode
from argparse          import ArgumentParser
from netrc             import netrc

class HTML_Requester (object) :

    def __init__ (self, args) :
        self.args     = args
        self.jar      = j = CookieJar ()
        self.opener   = urllib2.build_opener (urllib2.HTTPCookieProcessor (j))
        self.nextfile = args.file
    # end def __init__

    def open (self, filepart = None, data = None) :
        filepart = filepart or self.nextfile
        url = '/'.join (('https:/', self.args.host, self.args.file))
        rq = urllib2.Request (url, data)
        f  = self.opener.open (rq, timeout = 10)
        self.soup = BeautifulSoup (f)
        #purl  = f.geturl ()
        #pinfo = f.info ()
    # end def open

    def login (self) :
        self.open ()
        forms = self.soup.find_all ('form')
        for form in forms :
            if 'id' in form.attrs and form ['id'] == 'loginForm' :
                self.nextfile = form ['action']
                assert form ['method'] == 'post'
                break
        print self.nextfile
        d = dict \
            ( password      = self.args.password
            , userName      = self.args.username
            , selectedRealm = self.args.realm
            , loginType     = self.args.login_type
            , vpid_prefix   = self.args.vpid_prefix
            )
        self.open (data = urlencode (d))
        print self.soup.prettify ()
    # end def login

# end class HTML_Requester

def main () :
    cmd = ArgumentParser ()
    cmd.add_argument \
        ( '-F', '--file'
        , help    = 'File part of URL default=%(default)s'
        , default = 'sslvpn'
        )
    cmd.add_argument \
        ( '-H', '--host'
        , help    = 'Host part of URL default=%(default)s'
        , default = 'snx.lfrz.at'
        )
    cmd.add_argument \
        ( '-L', '--login-type'
        , help    = 'Login type, default=%(default)s'
        , default = 'Standard'
        )
    cmd.add_argument \
        ( '-p', '--password'
        , help    = 'Login password, not a good idea to specify on commandline'
        )
    cmd.add_argument \
        ( '-R', '--realm'
        , help    = 'Selected realm, default=%(default)s'
        , default = 'ssl_vpn'
        )
    cmd.add_argument \
        ( '-U', '--username'
        , help    = 'Login username'
        )
    cmd.add_argument \
        ( '-V', '--vpid-prefix'
        , help    = 'VPID prefix, default empty'
        , default = ''
        )
    args = cmd.parse_args ()
    if 'username' not in args or 'password' not in args :
        n = netrc ()
        a = n.authenticators (args.host)
        if a :
            un, dummy, pw = a
            if 'username' not in args :
                args ['username'] = un
            if 'password' not in args :
                args ['password'] = pw
        if 'password' not in args :
            password = getpass ('Password: ')
    rq = HTML_Requester (args)
    rq.login ()
# end def main ()

if __name__ == '__main__' :
    main ()
