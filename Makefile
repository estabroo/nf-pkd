# make likes to have at least one real rule
# this just runs the first rule in the sub-directory makefile
all:
	cd src/nf-pkd && $(MAKE)
	cp src/nf-pkd/nf-pkd bin
	cd src/nf-pkd-knock && $(MAKE)
	cp src/nf-pkd-knock/nf-pkd-knock bin

test:
	cd src/nf-pkd && $(MAKE) test
	cd src/nf-pkd-knock && $(MAKE) test

clean:
	rm bin/*
	rm src/nf-pkd/nf-pkd
	rm src/nf-pkd-knock/nf-pkd-knock
