import os
import sys
import struct

sys.path.append(os.path.dirname(__file__) + "/../..")
from tools import kallsyms64

#a -1 return on any function will abort the patch process, it is assumed we will print out the error reason
#all passed in values are offsets

def CreateBranch(from_addr, to_addr):
	#create a branch from one location to another
	return struct.pack("<I", (((to_addr - from_addr) >> 2) & 0x3ffffff) | 0x14000000)

def _OpcodeFixup(name, opcode, from_addr, to_addr):
	#fix up required opcodes as needed for this architecture.
	#We are given the original opcode, the location it was at and the location it is at now

	opcode = struct.unpack("<I", opcode)[0]
	if (opcode & 0x7c000000) == 0x14000000:
		BranchLoc = ((opcode & 0x3ffffff) << 2) + from_addr
		print "Detected branch to %08x for %s opcode, rewriting" % (BranchLoc, name)

		NewBranchLoc = BranchLoc - to_addr
		opcode = (opcode & 0xFC000000) | ((NewBranchLoc >> 2) & 0x3ffffff)
	elif (opcode & 0xff000010) == 0x54000000:
		#branch conditional, see if we can branch far enough
		BranchLoc = (((opcode & 0x00ffffe0) >> 5) << 2) + from_addr
		print "Detected conditional branch to %08x for %s opcode, rewriting" % (BranchLoc, name)

		NewBranchLoc = BranchLoc - to_addr
		if abs(NewBranchLoc) >= (1 << 20):
			print "New branch offset outside of 1MB range, unable to rewrite"
			return -1

		opcode = (opcode & 0xff00001f) | (((NewBranchLoc >> 2) & 0x7ffff) << 5)
	elif (opcode & 0x9f000000) == 0x90000000:
		#adrp, calculate new address
		ADRPOffset = ((opcode & 0x00ffffe0) >> 5) << 2
		ADRPOffset |= (opcode >> 29) & 0x3
		ADRPOffset <<= 12
		ADRPOffset += (from_addr & 0xfffff000)

		print "Detected adrp to %08x for %s opcode, rewriting" % (ADRPOffset, name)

		NewADRPOffset = ADRPOffset - (to_addr & 0xfffff000)
		NewADRPOffset >>= 12

		#insert new value
		opcode = (opcode & 0x9f00001f)
		opcode |= ((NewADRPOffset & 0x3) << 29)
		opcode |= ((NewADRPOffset >> 2) << 5) & 0x00ffffe0

	return struct.pack("<I", opcode)

def _GetPath(Filename):
	CurPath = os.path.dirname(os.path.abspath(__file__))
	return "%s/patches/%s" % (CurPath, Filename)

def _CheckPatchValid(name, Config):
	return architectures.RecompileIfChanged("aarch64", Config, name)

def _GetPatchHeaderSize(name, Config):
	if _CheckPatchValid(name, Config):
		return -1

	#we must return the maximum size returned by GetPatchBefore() otherwise we run the risk
	#of our inserted header data overwriting code it shouldn't overwrite
	File = os.stat(_GetPath("patch_" + name + ".bin"))
	return File.st_size

def _GetPatch(patchname, f, name, FunctionAddr, PatchAddr, Config, MapData):
	if _CheckPatchValid(patchname, Config):
		return -1

	#PatchAddr is the actual patch data we will be attached to, we are written above it
	#so keep this in mind for calculations

	#get the patch data
	PatchData = open(_GetPath("patch_" + patchname + ".bin"), "rb").read()

	#now read the original bytes, create a branch and update our patch before returning it
	PatchOffset = PatchData.find(struct.pack("<I", 0xfeedfeed))

	#get the original opcode
	f.seek(FunctionAddr)
	OrigOp = f.read(4)

	#calculate the address the opcode will be at
	NewLocation = PatchAddr - len(PatchData) + PatchOffset

	#do any needed fixups
	OrigOp = _OpcodeFixup(name, OrigOp, FunctionAddr, NewLocation)
	if type(OrigOp) == int:
		return -1

	#get branch opcode
	BranchOp = CreateBranch(NewLocation + 4, FunctionAddr + 4)

	#update our patch data
	PatchData = PatchData[0:PatchOffset] + OrigOp + BranchOp + PatchData[PatchOffset+len(OrigOp)+len(BranchOp):]

	#look at the map data and fill in a couple lookup values for got and init_got
	GotOffset = 0
	InitOffset = 0

	#MapData is an array of split entries from the map file
	for CurMapEntry in MapData:
		(SectionName, KernelAddress, FilePos, DataLen) = CurMapEntry
		if SectionName == ".got":
			GotOffset = int(KernelAddress, 16) + int(DataLen, 16) - 8
			if InitOffset:
				break

		elif SectionName == ".text.init_got":
			InitOffset = int(KernelAddress, 16)
			if GotOffset:
				break

	#calculate relative to our current patch location
	GotOffset = (GotOffset - PatchAddr) & 0xffffffffffffffff
	InitOffset = (InitOffset - PatchAddr) & 0xffffffffffffffff
	PatchData = PatchData[0:-16] + struct.pack("<QQ", GotOffset, InitOffset)

	return PatchData

def GetPatchBeforeHeaderSize(Config):
	return _GetPatchHeaderSize("before", Config)

def GetPatchBefore(f, name, FunctionAddr, PatchAddr, Config, MapData):
	return _GetPatch("before", f, name, FunctionAddr, PatchAddr, Config, MapData)

def GetPatchAfterHeaderSize(Config):
	return _GetPatchHeaderSize("after", Config)

def GetPatchAfter(f, name, FunctionAddr, PatchAddr, Config, MapData):
	return _GetPatch("after", f, name, FunctionAddr, PatchAddr, Config, MapData)

def get_kallsyms(vmlinux, PrintMsgs = 0):
	return kallsyms64.get_kallsyms(vmlinux, PrintMsgs)
