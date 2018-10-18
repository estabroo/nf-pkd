RELEASE_VERSION := $(shell cat metadata/version)

all:
	cd src/nf-pkd && $(MAKE)
	cp src/nf-pkd/nf-pkd bin
	cd src/nf-pkd-knock && $(MAKE)
	cp src/nf-pkd-knock/nf-pkd-knock bin

test:
	cd src/knock && $(MAKE) test
	cd src/nf-pkd && $(MAKE) test

clean:
	rm -f bin/*
	cd src/nf-pkd && $(MAKE) clean
	cd src/nf-pkd-knock && $(MAKE) clean
	cd src/knock && $(MAKE) clean

tag:
	git tag -m"release version ${RELEASE_VERSION}" ${RELEASE_VERSION}
