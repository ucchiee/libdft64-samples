pin-root := `pwd`/`ls -d */ | grep pin- | cut -d "/" -f 1`

.PHONY: build clean

build:
	export PIN_ROOT=$(pin-root) && cd src && $(MAKE)
	export PIN_ROOT=$(pin-root) && cd tools && $(MAKE)

clean:
	rm -rf tools/obj-intel64

