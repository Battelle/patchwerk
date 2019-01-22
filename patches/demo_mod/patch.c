#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mman.h>

//our required header to work our magic
#include <patcher.h>

HOOK_BEFORE(battelle_module_write)
{
	//get user passed in length to validate
	size_t len = Regs->Arg2;

	if(len > 512)
	{
		Regs->Ret0 = -EINVAL;
		return -1;
	}

	return 0;
}

HOOK_BEFORE(battelle_module_read)
{
	//get user passed in length to validate
	size_t len = Regs->Arg2;

	if(len > 512)
	{
		Regs->Ret0 = -EINVAL;
		return -1;
	}

	return 0;
}

#define STATE_SIZE 16
typedef struct IO_STRUCT
{
    unsigned long Size; //size of our struct
    unsigned int state_i;
    unsigned int STATE[STATE_SIZE];
} IO_STRUCT;

HOOK_BEFORE(battelle_module_ioctl)
{
	IO_STRUCT IOData;

	//get user passed in length to validate
	if(copy_from_user(&IOData, Regs->Arg2, sizeof(IO_STRUCT)) != 0)
	{
		Regs->Ret0 = -EFAULT;
		return -1;
	}

	//verify our structure size
	if(IOData.Size != sizeof(IOData))
	{
		Regs->Ret0 = -EINVAL;
		return -1;
	}

	if(IOData.state_i >= STATE_SIZE)
	{
		Regs->Ret0 = -EINVAL;
		return -1;
	}

	return 0;
}

