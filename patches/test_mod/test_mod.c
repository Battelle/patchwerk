#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>

//our required header to work our magic
#include <patcher.h>

//if this function exists then it will be called after the patch does some init work
/*
void patch_init()
{
}
*/

HOOK_AFTER(urandom_read)
{
	char TempBuffer[0x100];
	int i;
	int CopyLen;
	pid_t pid;

	//get user passed in values
	char __user *buffer = __user(Regs->Arg1);
	int len = Regs->Arg2;

	pid = task_pid_nr(current);
	printk(KERN_INFO "urandom_read (%d): %lx %lx %lx %lx\n", pid, Regs->Arg0, Regs->Arg1, Regs->Arg2, Regs->Arg3);

	//fill up our buffer with a pattern
	for(i = 0; i < sizeof(TempBuffer); i++)
		TempBuffer[i] = i;

	//apply the buffer to the requested data
	CopyLen = sizeof(TempBuffer);
	for(i = 0; i < len; i += sizeof(TempBuffer))
	{		
		if(CopyLen > (len - i))
			CopyLen = len - i;
		copy_to_user(&buffer[i], TempBuffer, CopyLen);
	}

	Regs->Ret0 = len;
}
