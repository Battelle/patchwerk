.text
.section .text

.global patch_before
.extern patch_before
patch_before:
	//store off the link register
	stp x29, x30, [sp, #-0x10]!

	//store off our params
	stp x6, x7, [sp, #-0x10]!
	stp x4, x5, [sp, #-0x10]!
	stp x2, x3, [sp, #-0x10]!
	stp x0, x1, [sp, #-0x10]!

	//0 for ret values
	mov x0, #0
	stp x0, x0, [sp, #-0x10]!

	//check if we need to init ourselves
	adr x14, patch_before_end
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
	mov x29, sp

	//branch to the attached function with a pointer to the params
	mov x0, sp
	bl patch_before_end

	//if x0 is -1 then skip calling the original function
	cmp x0, #-1
	b.eq patch_skip_call

	//restore the pushed valued and our original link register then fall into the attached code to handle everything
	//the called code was given a pointer to the values so it could modify params as needed
	add sp, sp, #0x10
	ldp x0, x1, [sp], #0x10
	ldp x2, x3, [sp], #0x10
	ldp x4, x5, [sp], #0x10
	ldp x6, x7, [sp], #0x10
	ldp x29, x30, [sp], #0x10

	//call the original opcode we overwrote then branch relative to where we hooked
.long 0xFEEDFEED
.long 0

patch_skip_call:
	//get the return value then adjust stack and return
	ldp x0, x1, [sp], #0x10
	add sp, sp, #0x40
	ldp x29, x30, [sp], #0x10
	ret

gotcheck_addr:
.quad 0

init_addr:
.quad 0

patch_before_end:
    
.size patch_before, .-patch_before
