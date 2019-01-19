#include <asm/memory.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <asm/pgtable.h>

.text
.section .text.init_got

.extern loadoffset
.extern gotaddr
.extern gotcount
.extern patchsize
.extern change_memory_common
.extern datastart
.extern datasize

.global init_got
.extern init_got
init_got:
	stp x29, x30, [sp, #-0x10]!
	stp x0, x1, [sp, #-0x10]!

	#we need to make sure our data area of memory is set for rwx due to writing data
	#get our data start location, mask it and calculate the number of pages we take up

	#set x10 to be our kernel base
	adr x10, init_got
	ldr x11, init_got_loc
	sub x10, x10, x11

	#get actual data page offset
	ldr x11, datastart_addr
	add x10, x10, x11
	mov x13, x10
	mov x14, #(PAGE_SIZE-1)
	and x13, x13, x14
	mvn x14, x14
	and x10, x10, x14

	#x10 - start page address
	#x13 - offset into page
	
	#add our page offset to the data size
	ldr x15, datasize_addr
	add x15, x15, x13

	#shift to get the page count and increment by 1 to get total page count
	lsr x15, x15, #PAGE_SHIFT
	add x15, x15, #1
	
	/*
	call change_memory_common which is arch specific, turn on write, turn off read only
	*/
    mov x0, x10
    mov x1, x15
	mov x2, #PTE_RDONLY
	eor x3, x3, x3
	bl change_memory_common

    mov x0, x10
    mov x1, x15
	mov x2, #PTE_WRITE
	mov x3, #1
	bl change_memory_common

	#set x14 to be our kernel base
	adr x14, init_got
	ldr x15, init_got_loc
	sub x14, x14, x15

	#x14 - kernel base to adjust all got entries by

	#fixup all got entries
	ldr x15, gotstart_addr
	add x15, x15, x14
	ldr x13, gotend_addr
	add x13, x13, x14

gotloop:
	sub x12, x13, x15
	cbz x12, gotdone

	#load and modify the value
	ldr x12, [x15]
	add x12, x12, x14
	str x12, [x15]

	#next entry
	add x15, x15, #8
	b gotloop

gotdone:

#ifdef __INIT_patch_init
	bl patch_init
#endif

	#return
	ldp x0, x1, [sp], #16	
	ldp x29, x30, [sp], #0x10
	ret

init_got_loc:
.quad init_got

datastart_addr:
.quad datastart

datasize_addr:
.quad datasize

gotstart_addr:
.quad gotstart

gotend_addr:
.quad gotend

.size init_got, .-init_got
