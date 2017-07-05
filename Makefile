# To use this Makefile, get a copy of my SF Release Tools
# git clone git://git.code.sf.net/p/sfreleasetools/code sfreleasetools
# And point the environment variable RELEASETOOLS to the checkout
ifeq (,${RELEASETOOLS})
    RELEASETOOLS=../releasetools
endif
LASTRELEASE:=$(shell $(RELEASETOOLS)/lastrelease -n)
VERSIONPY=snxvpnversion.py
VERSION=$(VERSIONPY)
README=README.rst
SRC=Makefile setup.py snxconnect.py snxconnect \
    MANIFEST.in $(README) README.html

USERNAME=schlatterbeck
PROJECT=snxvpn
PACKAGE=snxvpn
CHANGES=changes
NOTES=notes

all: $(VERSION)

$(VERSION): $(SRC)

dist: all
	python setup.py sdist --formats=gztar,zip

clean:
	rm -f MANIFEST $(VERSION) notes changes                       \
	      README.html README.aux README.dvi README.log README.out \
	      README.tex announce_pypi upload_pypi
	rm -rf dist build upload upload_homepage ReleaseNotes.txt
	rm -rf __pycache__

include $(RELEASETOOLS)/Makefile-sf
