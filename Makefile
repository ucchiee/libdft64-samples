pin-root := `pwd`/`ls -d */ | grep pin- | cut -d "/" -f 1`

.PHONY: build clean

build:
	export PIN_ROOT=$(pin-root) && cd src && $(MAKE)

clean:
	rm -f src/makefile
	rm -rf src/obj-intel64

