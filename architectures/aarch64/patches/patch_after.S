.text
.section .text

.global patch_after
.extern patch_after
patch_after:
	//store off and take over the link register return value
	stp x29, x30, [sp, #-0x10]!

	//store off our params
	stp x6, x7, [sp, #-0x10]!	
	stp x4, x5, [sp, #-0x10]!
	stp x2, x3, [sp, #-0x10]!
	stp x0, x1, [sp, #-0x10]!

	mov x29, sp
	adr x30, _end

	//call the original opcode we overwrote then branch relative to where we hooked
.long 0xFEEDFEED
.long 0

_end:
	//push the return value and then provide a pointer to the param list
	stp x0, x1, [sp, #-0x10]!

	//check if we need to init ourselves
	adr x14, patch_function
	ldr x15, gotcheck_addr
	add x15, x15, x14
	ldr x15, [x15]
	cmp x15, #0
	bne patch_continue

	//call the init function
	ldr x15, init_addr
	add x15, x15, x14
	blr x15

patch_continue:
	mov x0, sp

	bl patch_function

	//restore our original link register and return value and return to the original caller
	ldp x0, x1, [sp], #0x10
	add sp, sp, #0x40
	ldp x29, x30, [sp], #0x10
	ret

//relative offsets from our location for the got_init function and gotcheck location
gotcheck_addr:
.quad 0

init_addr:
.quad 0

patch_function:

.size patch_after, .-patch_after
