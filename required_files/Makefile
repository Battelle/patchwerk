include ../$(INCLUDE)

SUBFOLDER = ../patches/$(FOLDER)
OUTPUT = $(SUBFOLDER)/$(FOLDER).bin

CFILES = $(wildcard *.c)
OBJECTS = $(patsubst %.c,$(SUBFOLDER)/%.o,$(CFILES))

SUB_CFILES = $(wildcard $(SUBFOLDER)/*.c)
SUB_OBJECTS = $(patsubst %.c,%.o,$(SUB_CFILES))

SFILES = $(wildcard ../architectures/$(ARCH)/*.S)
SUB_SFILES = $(wildcard $(SUBFOLDER)/*.S)

#we need to control offset.o to the end so remove from the objects list
SOBJECTS = $(patsubst ../architectures/$(ARCH)/%.S,$(SUBFOLDER)/%.o,$(SFILES))
SUB_SOBJECTS = $(patsubst %.S,%.o,$(SUB_SFILES))

INCLUDEDIR += -I ../architectures/$(ARCH) -I ./

all: $(OBJECTS) $(SOBJECTS) $(SUB_OBJECTS) $(SUB_SOBJECTS) $(SUBFOLDER)/my_loader.lds
	@$(LD) -nostdlib -T $(SUBFOLDER)/my_loader.lds $(OBJECTS) $(SOBJECTS) $(SUB_OBJECTS) $(SUB_SOBJECTS) --static -o $(OUTPUT)-a
	@python ../tools/pack-elf.py -i $(OUTPUT)-a -o $(OUTPUT) -m $(SUBFOLDER)/$(FOLDER).map
	@rm -f $(OUTPUT)-a
	@rm -f $(SUBFOLDER)/my_loader.lds

$(SUBFOLDER)/my_loader.lds: $(OBJECTS) $(SOBJECTS) $(SUB_OBJECTS) $(SUB_SOBJECTS)
	@python ../tools/create-linker-script.py -s $(INCLUDE) -f $(SUBFOLDER) -k $(KALLSYMS) -w $(WHITELIST) -A $(ARCH) $(OBJECTS) $(SOBJECTS) $(SUB_OBJECTS) $(SUB_SOBJECTS)

$(SUBFOLDER)/%.o: $(SUBFOLDER)/%.S
	@$(GCC) $(CCFLAGS) $(INCLUDEDIR) $(DEFINES) -c $< -o $@

$(SUBFOLDER)/%.o: $(SUBFOLDER)/%.c
	@$(GCC) $(CCFLAGS) -std=gnu90 -nostdinc $(INCLUDEDIR) $(DEFINES) -Wno-main -fno-stack-protector -Wno-implicit-function-declaration -Wall -c $< -o $@ -Os -fno-asynchronous-unwind-tables -fPIC -pie

$(SUBFOLDER)/patch_fixups.o: ../architectures/$(ARCH)/patch_fixups.S $(SUB_OBJECTS) $(SUB_SOBJECTS)
	@$(GCC) $(CCFLAGS) $(INCLUDEDIR) $(DEFINES) -D __ASSEMBLY__ -D __INIT_`$(NM) $(SUB_OBJECTS) $(SUB_SOBJECTS) | grep patch_init | cut -d" " -f3`  -c $< -o $@

$(SUBFOLDER)/%.o: %.S
	@$(GCC) $(CCFLAGS) $(INCLUDEDIR) $(DEFINES) -D __ASSEMBLY__ -c $< -o $@

$(SUBFOLDER)/%.o: %.c
	@$(GCC) $(CCFLAGS) -std=gnu90 -nostdinc $(INCLUDEDIR) $(DEFINES) -Wno-main -fno-stack-protector -Wno-implicit-function-declaration -Wall -c $< -o $@ -Os -fno-asynchronous-unwind-tables -fPIC -pie

clean:
	@rm -f *.o $(SUBFOLDER)/*.bin $(SUBFOLDER)/functions.* $(SUBFOLDER)/my_loader.lds $(SUBFOLDER)/*.o $(SUBFOLDER)/*.map
