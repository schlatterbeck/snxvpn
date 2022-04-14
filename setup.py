#!/usr/bin/env python
# Copyright (C) 2017 Dr. Ralf Schlatterbeck Open Source Consulting.
# Reichergasse 131, A-3411 Weidling.
# Web: http://www.runtux.com Email: office@runtux.com
# All rights reserved
# ****************************************************************************
#
# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Library General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
# ****************************************************************************

from snxvpnversion import VERSION

from distutils.core import setup, Extension
license = 'BSD License'

description = []
f = open ('README.rst')
for line in f :
    description.append (line)
f.close ()

setup \
    ( name             = "snxvpn"
    , py_modules       = ['snxconnect', 'snxvpnversion']
    , version          = VERSION
    , description      =
        "Command-line utility to connect to a Checkpoint SSL VPN "
    , long_description = ''.join (description)
    , license          = license
    , author           = "Ralf Schlatterbeck"
    , author_email     = "rsc@runtux.com"
    , platforms        = 'Linux'
    , url              = "https://github.com/schlatterbeck/snxvpn"
    , scripts          = ['snxconnect']
    , install_requires = [ 'bs4', 'pycrypto', 'lxml', 'rsa' ]
    , classifiers      = \
        [ 'Development Status :: 3 - Alpha'
        , 'License :: OSI Approved :: ' + license
        , 'Operating System :: POSIX :: Linux'
        , 'Programming Language :: Python'
        , 'Intended Audience :: Developers'
        , 'Intended Audience :: Science/Research'
        , 'Intended Audience :: Information Technology'
        , 'Intended Audience :: System Administrators'
        , 'Programming Language :: Python :: 2.7'
        , 'Programming Language :: Python :: 3.4'
        , 'Programming Language :: Python :: 3.5'
        , 'Programming Language :: Python :: 3.6'
        ]
    )

