obj-m += ipo.o
DEBUG ?= 1
ifeq ($(DEBUG), 1)
	MYFLAGS=-DDEBUG
else
	MYFLAGS=-DNDEBUG
endif

pcpu_sw_netstats=$(shell grep pcpu_sw_netstats /lib/modules/$(shell uname -r)/build/include/linux/netdevice.h)

ifneq (,$(findstring pcpu_sw_netstats,$(pcpu_sw_netstats)))
	# Found
	MYFLAGS += -DPCPU_SW_NETSTATS
else
	# Not found
	MYFLAGS += -DNPCPU_SW_NETSTATS
endif

ccflags-y += $(MYFLAGS) -Wall -Werror
CC += $(MYFLAGS)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	EXTRA_CFLAGS="$(MY_CFLAGS)"
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean