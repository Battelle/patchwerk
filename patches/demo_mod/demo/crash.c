#include <stdio.h>
#include <string.h>
#include <linux/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int fd_b;
    char *TempBuffer;
    int BufferSize;

    if(argc != 2)
    {
        printf("Usage: %s len\n", argv[0]);
        return 0;
    }

    BufferSize = atoi(argv[1]);
    TempBuffer = (char *)malloc(BufferSize);
    if(TempBuffer == 0)
    {
        printf("Error allocating memory\n");
        return 0;
    }

    //connect to /dev/battelle and setup the key
    fd_b = open("/dev/battelle", O_RDWR);
    if(fd_b < 0)
    {
        printf("Error opening /dev/battelle\n");
        return 0;
    }

    memset(TempBuffer, 'A', BufferSize);
    if(write(fd_b, TempBuffer, BufferSize) != BufferSize)
    {
        printf("Error writing data to /dev/battelle\n");
        close(fd_b);
        return 0;
    }

    close(fd_b);
    printf("Wrote %d bytes to /dev/battelle\n", BufferSize);
    return 0;
}