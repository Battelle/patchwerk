import sys, os
import argparse
import subprocess
import shutil
import struct
import architectures

parser = argparse.ArgumentParser(description="Kernel patcher")
parser.add_argument("-A", dest="arch", required=True, choices=architectures.arch.keys(), help="Architecture to patch")
parser.add_argument("-i", dest="kernel_image", required=True, help="Kernel image")
parser.add_argument("-o", dest="output", default="", help="Output file of modified kernel")
parser.add_argument("-p", dest="patch", help="Folder holding patch code")
parser.add_argument("-c", dest="compile_only", default=False, action="store_true", help="Compile only, do not write image")
parser.add_argument("-s", dest="config", default="", help="Makefile config file for compiling (default <arch>.config)")
parser.add_argument("-w", dest="whitelist", required=True, help="Whitelist for kernel image of functions that can be overwritten")
parser.add_argument("-kallsyms", dest="get_kallsyms", default=False, action="store_true", help="Extract just kallsyms")
parser.add_argument("--clean", dest="clean", action="store_true", default=False, help="Make clean before compiling")

def DoPatch(f, p, arch, func, msg, FunctionName, FunctionAddr, KernelAddress, PatchDataLen, Config, MapData):
    #get the patch header data fixed up with the original location
    PatchHeaderData = func(f, FunctionName, FunctionAddr, KernelAddress, Config, MapData)
    if type(PatchHeaderData) == int:
        f.close()
        p.close()
        return -1
        
    #adjust for how much patch data we got and move backwards that amount
    f.seek(KernelAddress - len(PatchHeaderData))
    f.write(PatchHeaderData)

    #create a branch to this patch and insert it
    BranchOp = architectures.arch[arch].CreateBranch(FunctionAddr, KernelAddress - len(PatchHeaderData))
    f.seek(FunctionAddr)
    f.write(BranchOp)
    print "Wrote %d bytes to address %x for %s hook to %s with branch from %x to %x" % (len(PatchHeaderData) + PatchDataLen, KernelAddress - len(PatchHeaderData), msg, FunctionName, FunctionAddr, KernelAddress - len(PatchHeaderData))

    return 0

def main():
    params = parser.parse_args()

    #if no config then specify the default which is architecture specific
    if len(params.config) == 0:
        params.config = params.arch + ".config"

    #this is going to get large quickly, attempting to keep it clean
    kernel_data = open(params.kernel_image, "r").read()
    (entrycount, kallsyms_data) = architectures.arch[params.arch].get_kallsyms(kernel_data)
    if(entrycount == -1):
        print kallsyms_data
        return -1

    kallsymsfile = os.path.abspath(os.path.dirname(params.kernel_image)) + "/" + "kallsyms"
    print "Writing %d kallsym entries to %s" % (entrycount, kallsymsfile)

    #sort the entries for the file
    kallsyms_offsets = []
    for entry in kallsyms_data:
        kallsyms_offsets.append([entry, kallsyms_data[entry]])

    #sort by name and the offsets then write them
    kallsyms_offsets = sorted(kallsyms_offsets, key=lambda val: val[0])
    kallsyms_offsets = sorted(kallsyms_offsets, key=lambda val: val[1]["address"])
    f = open(kallsymsfile, "w")
    for entry in kallsyms_offsets:
        f.write("%016x %s %s\n" % (entry[1]["address"], entry[1]["type"], entry[0]))
    f.close()

    #if just kallsyms then end
    if params.get_kallsyms:
        return 0

    #see if certain options exist
    ParamReqs = [["p", params.patch]]

    #if not compile only then see if we are missing certain options
    if not params.compile_only:
        ParamReqs.append(["o", params.output])

    #check if we have a patch entry now
    for Entry in ParamReqs:
        if Entry[1] == None:
            print "%s: Error: argument -%s is required" % (sys.argv[0], Entry[0])
            return -1

    if params.clean:
        print "Cleaning %s" % (params.patch)
        s = subprocess.Popen(["make", "-C", "patches/" + params.patch, "clean", "INCLUDE=%s" % (params.config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ret = s.wait()

    print "Compiling %s" % (params.patch)
    if params.whitelist[0] != "/":
        params.whitelist = os.getcwd() + "/" + params.whitelist
    s = subprocess.Popen(["make", "-C", "patches/" + params.patch, "INCLUDE=%s" % (params.config), "KALLSYMS=%s" % (kallsymsfile), "ARCH=%s" % (params.arch), "WHITELIST=%s" % (params.whitelist)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    outdata = ""
    outerr =  ""
    while(s.poll() == None):
        (stdout, stderr) = s.communicate()
        outdata += stdout
        outerr += stderr

    if s.poll() != 0:
        print outdata
        print outerr
        sys.exit(0)

    PatchBinFile = "patches/%s/%s.bin" % (params.patch, params.patch)
    PatchSectionFile = "patches/%s/%s.map" % (params.patch, params.patch)

    if not os.path.isfile(PatchBinFile):
        print "Error in creating %s" % (PatchBinFile)
        return -1

    PatchBinLen = os.stat(PatchBinFile).st_size
    print "Wrote %d bytes to %s" % (PatchBinLen, PatchBinFile)

    #if they only want it compiled then exit
    if params.compile_only:
        return 0

    #copy the file, patch in the bin image, then modify mark_rodata_ro to call our init and modify the other location to call our code
    shutil.copyfile(params.kernel_image, params.output)

    #get our patch data along with the section mapping and patch info
    p = open(PatchBinFile, "rb")
    SectionInfo = open(PatchSectionFile, "r").read().split("\n")

    #split up the lines
    Sections = []
    for Entry in SectionInfo:
        if len(Entry):
            Sections.append(Entry.split())

    #now sort all entries based on the first field. We do this as we need .text.after to be after .text.before incase there is a before/after
    #patch of the same function
    Sections = sorted(Sections, key=lambda x: x[0], reverse=True)

    #open up the new kernel
    f = open(params.output, "r+b")

    #cycle through each section and dump it into the kernel then apply any required fixups and patch headers
    for CurSection in Sections:
        #get the line information
        (SectionName, KernelAddress, FilePos, DataLen) = CurSection
        KernelAddress = int(KernelAddress, 16)
        FilePos = int(FilePos, 16)
        DataLen = int(DataLen, 16)

        #seek into the kernel for where to write the patch data
        f.seek(KernelAddress)
        p.seek(FilePos)

        PatchData = p.read(DataLen)
        f.write(PatchData)

        #if this is one of our patches then look up the function name
        ValidSections = [".text.before.", ".text.after."]
        for CurValidSection in ValidSections:
            if SectionName.startswith(CurValidSection):
                #if our function name location doesn't match the original then we need to insert a branch into the original location
                FunctionName = ".".join(SectionName.split(".")[3:])

                #try converting the name to an integer, if it fails then look it up
                FunctionAddr = -1
                try:
                    FunctionAddr = int(FunctionName, 16)
                except:
                    pass

                #if we didn't convert it then look it up
                if FunctionAddr == -1:
                    if FunctionName not in kallsyms_data:
                        print "Error locating %s in kallsyms for patch" % (FunctionName)
                        f.close()
                        p.close()
                        return -1

                    FunctionAddr = kallsyms_data[FunctionName]["address"]

        #if this is a before or after hook then we need to add in the hook info
        if SectionName.startswith(".text.before."):
            #get the before patch header data fixed up with the original location
            if DoPatch(f, p, params.arch, architectures.arch[params.arch].GetPatchBefore, "before", FunctionName, FunctionAddr, KernelAddress, len(PatchData), params.config, Sections):
                return -1

        elif SectionName.startswith(".text.after."):
            #get the before patch header data fixed up with the original location
            if DoPatch(f, p, params.arch, architectures.arch[params.arch].GetPatchAfter, "after", FunctionName, FunctionAddr, KernelAddress, len(PatchData), params.config, Sections):
                return -1

        else:
            print "Wrote %d bytes to address %x for %s" % (DataLen, KernelAddress, SectionName)

    f.close()
    p.close()    

    #done
    return 0

if __name__ == "__main__":
    sys.exit(main())
