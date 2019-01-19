include ../../../$(INCLUDE)

patch_$(NAME).bin: patch_$(NAME).S
	$(GCC) -c $< -o $@-a
	@$(OBJCOPY) -O binary -j .text -j .rodata* -j .data* -j .got.plt -j .got -j .bss -j .offsets $@-a $@
	@rm -f $@-a

$(NAME): patch_$(NAME).bin
	@echo "Done"
