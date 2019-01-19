#ifndef __patcher_header
#define __patcher_header

//get our architecture specific structures, this header should define PatchRegs and AddressRegs
//any modifications to the structure will change the register state when the rest of the code continues after the hook
#include <patcher_arch.h>

//if the function void patch_init() exists it will be called when the first patch location is executed

//on a BEFORE hook, if the function returns -1 then the hooked function is skipped and the return code in Ret0 is returned

//macros for hooking before/after a function or replacing a function. All of these accept an address or function name
#define HOOK_BEFORE(FuncName) __attribute__((section(".text.before."#FuncName))) long HOOKBEFORE_##FuncName(struct PatchRegs *Regs)
#define HOOK_AFTER(FuncName) __attribute__((section(".text.after."#FuncName))) void HOOKAFTER_##FuncName(struct PatchRegs *Regs)

#endif