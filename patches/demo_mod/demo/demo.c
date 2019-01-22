#include <stdio.h>
#include <string.h>
#include <linux/ioctl.h>
#include <fcntl.h>

#define R 16
typedef struct WELL_INTERNAL_STRUCT
{
    unsigned int state_i;
    unsigned int STATE[R];
} WELL_INTERNAL_STRUCT;

typedef struct BATTELLE_IO_STRUCT
{
    unsigned long Size; //size of our struct
    WELL_INTERNAL_STRUCT WellState;
} BATTELLE_IO_STRUCT;

unsigned int Table[256];

void GenerateTable()
{
    unsigned int i, j;
    unsigned int x;
    for (i = 0; i < 256; i++)
    {
        x = i << 24;
        for (j = 8; j > 0; j--)
        {
            if(x & 0x80000000)
                x = (x << 1) ^ 0x04c11db7;
            else
                x <<= 1;
        }

        Table[i] = x;
    }
}

void GenerateState(WELL_INTERNAL_STRUCT *WellState, char *Key)
{
    //generate a state based on the user provided key
    int i, x;
    int KeyLen;

    KeyLen = strlen(Key);
    memset(WellState, 0, sizeof(WELL_INTERNAL_STRUCT));

    //copy the key across all states
    for(i = 0; (i + KeyLen) < sizeof(WellState->STATE); i+= KeyLen)
        memcpy(((char *)WellState->STATE + i), Key, KeyLen);

    //generate the crc table
    GenerateTable();

    //now scramble the state a bit more
    for(x = 0; x < KeyLen; x++)
    {
        for(i = 0; i < R; i++)
        {
            WellState->STATE[i] ^= Table[(WellState->STATE[(i + 1 + (Key[x] & 0x0f)) % R]) & 0xff];
            WellState->STATE[i] ^= Table[(WellState->STATE[(i - 1 - (Key[x] >> 4)) % R]) & 0xff];
        }
    }
}

void crypt(char *infile, char *outfile)
{
    BATTELLE_IO_STRUCT IOState;
    char Password[256];
    int fd_b, fd_in, fd_out;
    char TempBuffer[512];
    int BytesOut;
    int ReadBytes;

    write(1, "Password: ", 10);
    fgets(Password, sizeof(Password) - 1, stdin);
    Password[sizeof(Password) - 1] = 0;

    //setup the state
    IOState.Size = sizeof(IOState);
    GenerateState(&IOState.WellState, Password);

    //connect to /dev/battelle and setup the key
    fd_b = open("/dev/battelle", O_RDWR);
    if(fd_b < 0)
    {
        printf("Error opening /dev/battelle\n");
        return;
    }

    //setup the ioctl
    if(ioctl(fd_b, _IOR('b','a', char *), &IOState))
    {
        printf("Error with IOCTL call\n");
        close(fd_b);
        return;
    }

    //open up the file to encrypt
    fd_in = open(infile, O_RDONLY);
    if(fd_in < 0)
    {
        printf("Error opening %s for reading\n", infile);
        close(fd_b);
        return;
    }

    fd_out = creat(outfile, 0777);
    if(fd_out < 0)
    {
        printf("Error opening %s for writing\n", outfile);
        close(fd_in);
        close(fd_b);
        return;
    }

    //read blocks of 512 bytes from in and write to out after passing through the driver
    BytesOut = 0;
    while(1)
    {
        memset(TempBuffer, 0, sizeof(TempBuffer));
        ReadBytes = read(fd_in, TempBuffer, 512);
        if(ReadBytes == 0)
            break;

        write(fd_b, TempBuffer, 512);
        read(fd_b, TempBuffer, 512);
        write(fd_out, TempBuffer, 512);

        BytesOut += 512;
    };

    close(fd_in);
    close(fd_out);
    close(fd_b);

    printf("Wrote %d bytes to %s\n", BytesOut, outfile);
}

int main(int argc, char **argv)
{
    if(argc != 3)
    {
        printf("Usage: %s InFile OutFile\n", argv[0]);
        return 0;
    }

    crypt(argv[1], argv[2]);
    return 0;
}