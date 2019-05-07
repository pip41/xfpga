PWD := ${shell pwd}
KERNELDIR := ${PWD}/../../../../linux/kernel/linux

TOOLCHAIN_ABI := -march=octeon3 -mabi=64
CROSS := mips64-octeon-linux-gnu-

default: all
obj-m := xfpga.o

all:
	${MAKE} -C ${KERNELDIR} M=${PWD} ARCH=mips CROSS_COMPILE=${CROSS} CFLAGS="${TOOLCHAIN_ABI}" modules

clean:
	rm -Rf *.mod.c *.o *.ko .*cmd modules.order Module.symvers .tmp_versions

