mkfile_path := $(shell pwd)/.
current_dir := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))

all:
	@make -C ../../required_files FOLDER=$(current_dir) INCLUDE=$(INCLUDE) KALLSYMS=$(KALLSYMS) ARCH=$(ARCH) WHITELIST=$(WHITELIST)

clean:
	@make -C ../../required_files clean FOLDER=$(current_dir) INCLUDE=$(INCLUDE)
