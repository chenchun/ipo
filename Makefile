
obj-m += ipo.o
DEBUG ?= 1
ifeq ($(DEBUG), 1)
    MYFLAGS =-g -DDEBUG
else
    MYFLAGS=-g -DNDEBUG
endif

ccflags-y += ${MYFLAGS}
CC += ${MYFLAGS}

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean