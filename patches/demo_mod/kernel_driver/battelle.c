#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

//must be power of 2
#define STATE_SIZE 16
typedef struct BATTELLE_RANDOM_STRUCT
{
    unsigned int state_i;
    unsigned int STATE[STATE_SIZE];
} BATTELLE_RANDOM_STRUCT;

unsigned int BattelleRandom (BATTELLE_RANDOM_STRUCT *s)
{
    int i;
    unsigned int NewBit;

    //rotate all states and calculate a new bit for the LFSR
    NewBit = 0;
    for(i = 0; i < (STATE_SIZE - 1); i++)
    {
        //get 3 bits from each state
        NewBit ^= ((s->STATE[i] >> i) ^ (s->STATE[i] >> ((i + 3) % 32)) ^ (s->STATE[i] >> ((i + 11) % 32))) & 1;
        s->STATE[i] = (s->STATE[i] << 1) | (s->STATE[i + 1] >> 31);
    }
    s->STATE[STATE_SIZE - 1] = (s->STATE[STATE_SIZE - 1] << 1) | NewBit;

    //change the state we are looking at and return a value accordingly
    s->state_i = (s->state_i + 1) & (STATE_SIZE - 1);
    return s->STATE[s->state_i] ^ s->STATE[(s->state_i + 3) % STATE_SIZE] ^ (~s->STATE[(s->state_i + (STATE_SIZE / 2)) % STATE_SIZE]) ^ (~s->STATE[(s->state_i + (STATE_SIZE / 2) + 5) % STATE_SIZE]);
}

#define BUFFER_SIZE 512

typedef struct BATTELLE_IO_STRUCT
{
    unsigned long Size; //size of our struct
    BATTELLE_RANDOM_STRUCT State;
} BATTELLE_IO_STRUCT;

typedef struct BATTELLE_INTERNAL_STRUCT
{
    BATTELLE_RANDOM_STRUCT State;
    unsigned int Buffer[BUFFER_SIZE / sizeof(unsigned int)];
} BATTELLE_INTERNAL_STRUCT;

ssize_t battelle_module_write(struct file * file, const char * buf, size_t count, loff_t *ppos)
{
    //copy to our temporary buffer
    BATTELLE_INTERNAL_STRUCT *priv_data = (BATTELLE_INTERNAL_STRUCT *)file->private_data;
    int i;

    //make sure count is a multiple of 8
    count = (count + 7) & ~7;

    //this is bad due to not checking length
    if(copy_from_user(priv_data->Buffer, buf, count) != 0)
        return -EFAULT;

    //modify the data
    for(i = 0; i < count / sizeof(unsigned int); i++)
        priv_data->Buffer[i] ^= BattelleRandom(&(priv_data->State));

    return count;
}

ssize_t battelle_module_read(struct file * file, char * buf, size_t count, loff_t *ppos)
{
    //copy from our buffer to their buffer, this is bad as we don't check the request length
    BATTELLE_INTERNAL_STRUCT *priv_data = (BATTELLE_INTERNAL_STRUCT *)file->private_data;
    if(copy_to_user(buf, priv_data->Buffer, count) != 0)
        return -EFAULT;

    //wipe our data out
    memset(priv_data->Buffer, 0, BUFFER_SIZE);
	return count;
}

long battelle_module_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    BATTELLE_IO_STRUCT IOData;
    BATTELLE_INTERNAL_STRUCT *priv_data;

    //allow changing the seed if the cmd is valid
    if(cmd == _IOR('b', 'a', char *))
    {
        //should be our data, confirm
        if(copy_from_user(&IOData, (char *)arg, sizeof(BATTELLE_IO_STRUCT)) != 0)
            return -EFAULT;

        //if size matches then copy out the state
        if(IOData.Size == sizeof(BATTELLE_IO_STRUCT))
        {
            priv_data = (BATTELLE_INTERNAL_STRUCT *)filp->private_data;

            //this is bad, we don't check that state is a valid value between 0 and 15
            memcpy(&(priv_data->State), &IOData.State, sizeof(BATTELLE_RANDOM_STRUCT));
            return 0;
        }
    }

    //invalid
	return -EINVAL;
}

int battelle_module_open(struct inode *inode, struct file *filp)
{
    filp->private_data = kmalloc(sizeof(BATTELLE_INTERNAL_STRUCT), GFP_KERNEL);
    if(filp->private_data == NULL)
        return -ENOMEM;

    memset(filp->private_data, 0, sizeof(BATTELLE_INTERNAL_STRUCT));
    return 0;
}

int battelle_module_release(struct inode *inode, struct file *filp)
{
    if(filp->private_data)
    {
        //wipe the data out for safety
        memset(filp->private_data, 0, sizeof(BATTELLE_INTERNAL_STRUCT));
        kfree(filp->private_data);
    }

    return 0;
}

static const struct file_operations battelle_module_fops = {
	.owner		= THIS_MODULE,
	.read		= battelle_module_read,
	.write		= battelle_module_write,
    .open       = battelle_module_open,
    .release    = battelle_module_release,
	.unlocked_ioctl = battelle_module_ioctl,
};

static struct miscdevice battelle_module_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "battelle",
	.fops = &battelle_module_fops,
    .mode = S_IRUSR | S_IWUSR,
};

static int __init
battelle_module_init(void)
{
	int ret;

	//register the device
	ret = misc_register(&battelle_module_dev);
	if (ret)
		printk(KERN_ERR "Unable to register Battelle misc device\n");

	return ret;
}

module_init(battelle_module_init);

static void __exit
battelle_module_exit(void)
{
	misc_deregister(&battelle_module_dev);
}

module_exit(battelle_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Battelle/Jewell Seay");
MODULE_DESCRIPTION("patchwerk test module");
MODULE_VERSION("1.0");