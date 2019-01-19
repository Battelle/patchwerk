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

//if this function exists then it will be called after the patch does some init work
/*
void patch_init()
{
}
*/

char *strcasestr(char *a, char *b)
{
	//poor man's search for b inside of a case insensitive
	char *CurPos;
	int blen;

	CurPos = a;
	blen = strlen(b);
	while(*CurPos)
	{
		if(strncasecmp(CurPos, b, blen) == 0)
			return CurPos;

		CurPos++;
	}

	return 0;
}

HOOK_AFTER(tty_write)
{
	if(Regs->Arg4)
		Regs->Ret0 = Regs->Arg5;
}

HOOK_BEFORE(tty_write)
{
	char *TempBuffer;
	int count;
	char *CurPos;
	char *LastPos;
	int NewPos;

	char EmptyBuffer[1024];

	//get user passed in values
	char __user *buffer = __user(Regs->Arg1);
	int len = Regs->Arg2;

	//copy the buffer to a local buffer then scan it for the word "linux"
	if(len > (sizeof(EmptyBuffer) - 1))
		TempBuffer = __kmalloc(len + 1, GFP_KERNEL);
	else
		TempBuffer = EmptyBuffer;

	copy_from_user(TempBuffer, buffer, len);
	TempBuffer[len] = 0;

	//cycle until we can't find "linux" any more
	CurPos = TempBuffer;
	count = 0;
	while(CurPos = strcasestr(CurPos, "linux"))
	{
		CurPos += 5;
		count++;
	}

	//if no linux then just return without any changes
	if(!count)
	{
		if(TempBuffer != EmptyBuffer)
			kfree(TempBuffer);
		Regs->Arg4 = 0;
		return 0;
	}

	//found entries, reallocate a new string that is large enough
    //we need a userspace address as the tty output does validation
    unsigned long unused = 0;
    unsigned long page_size = (((len + (count * 3) + 1) >> PAGE_SHIFT) + 1) << PAGE_SHIFT;
    down_write(&current->mm->mmap_sem);
    unsigned char *mm_base = do_mmap_pgoff(NULL, 0x0000001122330000, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &unused);
    up_write(&current->mm->mmap_sem);

    //if we failed don't do anything
    if(mm_base != 0x0000001122330000)
    {
		if(TempBuffer != EmptyBuffer)
			kfree(TempBuffer);
		Regs->Arg4 = 0;
		return 0;       
    }

	CurPos = TempBuffer;
	NewPos = 0;
	while(CurPos)
	{
		//go find where "linux" is
		LastPos = CurPos;
		CurPos = strcasestr(CurPos, "linux");

		//if no entry then set it to the end of TempBuffer
		if(!CurPos)
		{
			copy_to_user(&mm_base[NewPos], LastPos, &TempBuffer[len] - LastPos);
			NewPos += &TempBuffer[len] - LastPos;
			break;
		}

		//copy from last up to CurPos
		copy_to_user(&mm_base[NewPos], LastPos, CurPos - LastPos);

		//add in TempleOS
		NewPos += (CurPos - LastPos);
		copy_to_user(&mm_base[NewPos], "TempleOS", 8);
		NewPos += 8;
	
		//skip "linux"
		CurPos += 5;
	};

	//free our first buffer
	if(TempBuffer != EmptyBuffer)
		kfree(TempBuffer);

	//change our buffer
	Regs->Arg1 = mm_base;

	//change length
	Regs->Arg2 = NewPos;

	//store off our pointer so we can lie about number of characters printed on return
	Regs->Arg4 = mm_base;
	Regs->Arg5 = len;
	return 0;
}
