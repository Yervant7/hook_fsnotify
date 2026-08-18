
ifndef KP_DIR
    KP_DIR = KPM-Headers
endif

CC = aarch64-none-elf-gcc
LD = aarch64-none-elf-ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/$(dir))

objs := hook_fsnotify.o

all: hook_fsnotify.kpm

hook_fsnotify.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
