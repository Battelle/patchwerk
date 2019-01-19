import sys, os
import subprocess
import argparse
from elftools.elf.elffile import ELFFile

parser = argparse.ArgumentParser(description="ELF Packer")
parser.add_argument("-i", dest="input", required=True, help="Input file")
parser.add_argument("-o", dest="output", required=True, help="Output file")
parser.add_argument("-m", dest="map", required=True, help="Output file for map information")

def main():
    #take an elf file and pack all of the sections together that are required
    params = parser.parse_args()

    f = open(params.input, "rb")
    o = open(params.output, "wb")
    m = open(params.map, "w")
    elf = ELFFile(f)

    #if a section starts with one of these then we will rip it out of the file
    ValidHeaders = [".text", ".rodata", ".data", ".got"]
    DataLen = 0

    #get maximum length for the fields
    NameWidth = 0
    AddrWidth = 0
    SizeWidth = 0
    DataWidth = 0
    for SectionID in xrange(0, elf.num_sections()):
        CurSection = elf.get_section(SectionID)

        for ValidEntry in ValidHeaders:
            if CurSection.name.startswith(ValidEntry):
                CurSection = elf.get_section(SectionID)
                if len(CurSection.name) > NameWidth:
                    NameWidth = len(CurSection.name)

                if len("%x" % CurSection.header.sh_addr) > AddrWidth:
                    AddrWidth = len("%x" % CurSection.header.sh_addr)

                if len("%x" % CurSection.data_size) > SizeWidth:
                    SizeWidth = len("%x" % CurSection.data_size)

                DataWidth += CurSection.data_size
                break

    #fix DataWidth
    DataWidth = len("%x" % DataWidth)

    #write all sections out
    for SectionID in xrange(0, elf.num_sections()):
        CurSection = elf.get_section(SectionID)

       
        #if we have a valid header then write it out
        for ValidEntry in ValidHeaders:
            if CurSection.name.startswith(ValidEntry):
                DataStart = DataLen
                o.write(CurSection.data())

                #add padding if we are not 4 byte aligned to allow easier disassembly
                Padding = 0
                if CurSection.data_size & 3:
                    Padding = 4 - (CurSection.data_size & 3)
                    o.write("\x00" * Padding)

                DataLen += CurSection.data_size + Padding
                m.write("%-{}s %{}x %{}x %{}x\n".format(NameWidth + 1, AddrWidth + 1, DataWidth + 1, SizeWidth + 1) % (CurSection.name, CurSection.header.sh_addr, DataStart, CurSection.data_size))
                break

    f.close()
    o.close()
    m.close()

    print "Wrote %d bytes to %s" % (DataLen, params.output)
    return 0

if __name__ == "__main__":
	sys.exit(main())