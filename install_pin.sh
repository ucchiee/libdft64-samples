#!/bin/bash
set -eux
PREFIX=${PREFIX:-`pwd`}

case "$(uname -s)" in
    Darwin)
        echo "OS: Mac OS X"
        TAR_NAME="pin-3.20-98437-gf02b61307-clang-mac"
        ;;
    Linux)
        echo "OS: Linux"
        TAR_NAME="pin-3.20-98437-gf02b61307-gcc-linux"
        ;;
    CYGWIN* | MINGW32* | MSYS* | MINGW*)
        # echo "MS Windows"
        ;;
    *)
        # echo "Other OS"
        ;;
esac

wget https://software.intel.com/sites/landingpage/pintool/downloads/${TAR_NAME}.tar.gz
tar -C ${PREFIX} -xzf ${TAR_NAME}.tar.gz
rm ${TAR_NAME}.tar.gz

set +x
echo "Please set:"
echo "export PIN_ROOT=${PREFIX}/${TAR_NAME}"

# create symlink
PINDIR=`ls -d */ | grep pin- | cut -d "/" -f 1`
CURDIR=`pwd`
pin_makefile="$CURDIR/$PINDIR/source/tools/MyPinTool/makefile"
mkdir -p src
ln -fs "$pin_makefile" src/makefile
echo "created symlink to src/makefile"

