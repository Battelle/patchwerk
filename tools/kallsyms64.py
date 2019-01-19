import sys, os
import struct
import binascii

def get_kallsyms(vmlinux, PrintMsgs = 0):
    CurTablePos = 0
    for CurPos in xrange(0, len(vmlinux), 256):
        TotalEntries = struct.unpack("<q", vmlinux[CurPos:CurPos+8])[0]
        if TotalEntries >= 10000 and TotalEntries <= 500000:
            #see if the value after it is all 0's to the next alignment
            if vmlinux[CurPos+8:CurPos+0x100-8] == "\x00"*(0x100-16):
                #attempt to look at the table following it and see if it makes sense
                CompressedNameEntries = []
                CurTablePos = CurPos + 0x100

                #check entries
                Failed = False
                for i in xrange(0, TotalEntries):
                    EntryLength = ord(vmlinux[CurTablePos])
                    #name can't be 0 and max per kallsyms.c is 128
                    if (EntryLength == 0) or (EntryLength > 128):
                        Failed = True
                        break

                    CompressedNameEntries.append(vmlinux[CurTablePos+1:CurTablePos+1+EntryLength])
                    CurTablePos += 1 + EntryLength

                if not Failed:
                    break

    if CurTablePos == 0:
        return (-1, "Unable to locate compressed name table")

    #get length of the compressed name table
    CompressNameTableStart = CurPos + 0x100
    CompressNameTableEnd = CurTablePos
    CompressedNameLength = CompressNameTableEnd - CompressNameTableStart

    #detect how many index entries, 256 per
    IndexTableStart = ((CurTablePos >> 8) + 1) << 8
    IndexCount = (TotalEntries + 255) / 256

    #check the entries
    CurIndexPos = IndexTableStart
    for i in xrange(0, IndexCount):
        EntryVal = struct.unpack("<Q", vmlinux[CurIndexPos:CurIndexPos+8])[0]
        if EntryVal > CompressedNameLength:
            Failed = True
            break

        CurIndexPos += 8

    if Failed:
        return (-1, "Error validating index table")

    IndexTableEnd = IndexTableStart + (8 * IndexCount)

    #get the decode table
    DecodeTableStart = ((IndexTableEnd >> 8) + 1) << 8
    DecodeTable = []
    DecodeTablePos = DecodeTableStart
    for i in xrange(0, 256):
        CurText = ""
        while(ord(vmlinux[DecodeTablePos])):
            CurText += vmlinux[DecodeTablePos]
            DecodeTablePos += 1

        DecodeTable.append(CurText)
        DecodeTablePos += 1

    DecodeTableEnd = DecodeTablePos

    if PrintMsgs:
        print "Total Entry Location 0x%x, count %d" % (CurPos, TotalEntries)
        print "Compressed Name table 0x%x to 0x%x" % (CompressNameTableStart, CompressNameTableEnd)
        print "Index table 0x%x to 0x%x" % (IndexTableStart, IndexTableEnd)
        print "Decode table 0x%x to 0x%x" % (DecodeTableStart, DecodeTableEnd)

    #decode all of the symbols
    DecompressedNames = []
    for CompressedEntry in CompressedNameEntries:
        CurName = ""
        for CurNameEntry in CompressedEntry:
            CurName += DecodeTable[ord(CurNameEntry)]

        DecompressedNames.append([CurName[0], CurName[1:]])

    #detect if we have an offset setup or not by looking at the previous 256 bytes, first 8 mask to a page boundary and the rest are 0
    kallsym_data = {}
    if (vmlinux[CurPos-0xf8:CurPos] == "\x00"*248) and ((struct.unpack("<Q", vmlinux[CurPos-0x100:CurPos-0xf8])[0] & 0xfff) == 0):
        #previous 256 bytes are 0, may be the offset setup, if the previous is 0 then
        #we have an empty table otherwise offsets
        if vmlinux[CurPos-0x200:CurPos-0x100] == "\x00"*256:
            return (-1, "Found empty address table")

        else:
            #calculate beginning of the table
            AddressTableStart = (CurPos - 0x100 - (TotalEntries * 4)) & ~0xff
            AddressTableEnd = AddressTableStart + (TotalEntries * 4)

            if PrintMsgs:
                print "Offset address table 0x%x to 0x%x" % (AddressTableStart, AddressTableEnd)

            #get the offset assigned
            Offset = struct.unpack("<Q", vmlinux[CurPos-0x100:CurPos-0x100+8])[0]
            if PrintMsgs:
                print "Offset: %016x" % (Offset)

            for i in xrange(0, TotalEntries):
                Address = struct.unpack("<i", vmlinux[AddressTableStart+(i*4):AddressTableStart+(i*4)+4])[0]
                kallsym_data[DecompressedNames[i][1]] = {"address": Address, "type": DecompressedNames[i][0]}
                #print "%016x %s %s" % (Address + Offset, DecompressedNames[i][0], DecompressedNames[i][1])


    else:
        #calculate beginning of the table
        AddressTableStart = (CurPos - (TotalEntries * 8)) & ~0xff
        AddressTableEnd = AddressTableStart + (TotalEntries * 8)
        print "Fixed address table %x - %x" % (AddressTableStart, AddressTableEnd)

        #calculate an offset value, the extra 0x2000 is due to buildroot kicking out a MZ image so we have to ignore the header
        OffsetAdjustment = struct.unpack("<Q", vmlinux[AddressTableStart:AddressTableStart+8])[0] - 0x2000
        print "Adjusting all values by %016x" % (OffsetAdjustment)
        for i in xrange(0, TotalEntries):
            Address = struct.unpack("<Q", vmlinux[AddressTableStart+(i*8):AddressTableStart+(i*8)+8])[0]
            kallsym_data[DecompressedNames[i][1]] = {"address": Address - OffsetAdjustment, "type": DecompressedNames[i][0]}
            #print "%016x %s %s" % (Address - OffsetAdjustment, DecompressedNames[i][0], DecompressedNames[i][1])


    return (len(kallsym_data), kallsym_data)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print "Usage: %s <linux-kernel-image>" % (sys.argv[0])
        sys.exit(0)

    vmlinux = open(sys.argv[1],"r").read()
    (count, kallsyms_data) = get_kallsyms(vmlinux, 1)

    if(count == -1):
        print kallsyms_data
        sys.exit(0)

    print "Found symbols"

    #get all offsets into a list we can sort as it is returned in a dictionary for lookup by name
    kallsyms_offsets = []
    for entry in kallsyms_data:
        kallsyms_offsets.append([entry, kallsyms_data[entry]])

    #sort by name and the offsets then output them
    kallsyms_offsets = sorted(kallsyms_offsets, key=lambda val: val[0])
    kallsyms_offsets = sorted(kallsyms_offsets, key=lambda val: val[1]["address"])
    for entry in kallsyms_offsets:
        print  "%016x %s %s" % (entry[1]["address"], entry[1]["type"], entry[0])
