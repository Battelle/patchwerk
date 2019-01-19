#ifndef __patcher_aarch64
#define __patcher_aarch64

//our architecture specific structures

typedef struct PatchRegs
{
    void *Ret0;
    void *Ret1;
    void *Arg0;
    void *Arg1;
    void *Arg2;
    void *Arg3;
    void *Arg4;
    void *Arg5;
    void *Arg6;
    void *Arg7;
} PatchRegs;

#endif