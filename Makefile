pin-root := `pwd`/`ls -d */ | grep pin- | cut -d "/" -f 1`

.PHONY: build clean

build:
	export PIN_ROOT=$(pin-root) && cd src && $(MAKE)
	export PIN_ROOT=$(pin-root) && cd tool && $(MAKE)

clean:
	rm -rf tool/obj-intel64

