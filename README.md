# NullPin

Template for creating Pintool.
Can be used for estimating the overhead of Pin.

## download pin

```bash
./install_pin.sh
```

## initialize libdft64

```bash
./init_libdft.sh
```

## build pintool

```bash
make
```

## build test program

```
cd test
gcc test.c
cd -
```

## how to run pintool

```bash
./pin-3.20-98437-gf02b61307-gcc-linux/pin -t tool/obj-intel64/main.so -func test -arg_index 0 -arg_size 4 -- test/a.out
```

## Note

- libdft64 only support linux
