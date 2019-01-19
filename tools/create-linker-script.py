import sys, os
import subprocess
import argparse
from elftools.elf.elffile import ELFFile

#add parent folder to our search path so we can access architectures
currentdir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(currentdir))

import architectures

parser = argparse.ArgumentParser(description="Linker script creator")
parser.add_argument("-A", dest="arch", required=True, choices=architectures.arch.keys(), help="Architecture to patch")
parser.add_argument("-k", dest="kallsyms", required=True, help="kallsyms file")
parser.add_argument("-s", dest="config", required=True, help="Path to config file, relative to parent directory")
parser.add_argument("-f", dest="subfolder", required=True, help="Subfolder to write to")
parser.add_argument("-w", dest="whitelist", required=True, help="File containing whitelist of functions to overwrite")
parser.add_argument("objectfiles", nargs="+", help="Object files to parse")

def GetSymbols(Filename):
	#return a dictionary of symbol/address/size combinations

	AllSymbols = {}

	Data = open(Filename, "r").read().split("\n")

	PrevEntry = None
	for Entry in Data:
		CurEntry = Entry.split()
		if len(CurEntry) <= 1:
			continue

		#we expect the format to be "address type funcname" with an optional hex size after

		#add in the entry and indicate the type
		AllSymbols[CurEntry[2]] = {"address": int(CurEntry[0], 16), "size": 0, "type": CurEntry[1].lower(), "name": CurEntry[2]}

		#if size is appended then add it otherwise calculate it based on the previous entrty
		if len(CurEntry) >= 4:
			AllSymbols[CurEntry[2]]["size"] = int(CurEntry[3], 16)
		else:
			#calculate the previous entry size
			if PrevEntry:
				AllSymbols[PrevEntry]["size"] = int(CurEntry[0], 16) - AllSymbols[PrevEntry]["address"]
			PrevEntry = CurEntry[2]

	return AllSymbols

def GetObjectData(Filename, AllSymbols):
	#get a dump of the exported objects and see what we need to fill in, we use  the readelf tool due to potential file differences
	#from what any python elf parser may expect. We expect aarch64-linux-android-readelf is in the path
	f = open(Filename, "rb")
	elf = ELFFile(f)

	#go through each entry and find the undefined entries, see if they are in our list
	ElfData = dict()
	ElfData["NeededData"] = []
	ElfData["PatchFuncs"] = []
	ElfData["ExternalSymbols"] = []
	ElfData["DefinedSymbols"] = []
	ElfData["TextSize"] = 0
	ElfData["RODataSize"] = 0
	ElfData["DataSize"] = 0
	ElfData["BSSSize"] = 0

	SymbolSection = elf.get_section_by_name(".symtab")
	AddedSections = []
	for Entry in xrange(0, SymbolSection.num_symbols()):
		Symbol = SymbolSection.get_symbol(Entry)

		#if undefined then see if we have a symbol for it
		if (Symbol.entry.st_shndx == "SHN_UNDEF") and (Symbol.name in AllSymbols):
			ElfData["NeededData"].append(Symbol.name)

		elif (Symbol.entry.st_info.bind == "STB_GLOBAL") and (Symbol.entry.st_shndx == "SHN_UNDEF"):
			#unknown symbol, add it to our external list
			ElfData["ExternalSymbols"].append(Symbol.name)

		elif (Symbol.entry.st_info.bind == "STB_GLOBAL") and (Symbol.entry.st_shndx == "SHN_COMMON"):
			#symbol is part of the BSS itself
			ElfData["BSSSize"] += Symbol.entry.st_size

		elif Symbol.name.split("_")[0] in ["HOOKBEFORE", "HOOKAFTER"]:
			#add a known symbol
			ElfData["DefinedSymbols"].append(Symbol.name)
			AddedSections.append(elf.get_section(Symbol.entry.st_shndx).name)

			#it is one of our special entries, add it
			#note the size of the function may not match the section due to some architectures adding extra data
			#so look up the section size
			FuncName = Symbol.name.split("_")
			PatchFuncEntry = dict()
			PatchFuncEntry["type"] = FuncName[0]
			PatchFuncEntry["name"] = "_".join(FuncName[1:])
			PatchFuncEntry["address"] = -1
			PatchFuncEntry["kallsyms"] = 1

			#generate the section name and look it up to get the proper size
			if FuncName[0][0:4] == "HOOK":
				FuncName[0] = FuncName[0][4:]
			SymbolName = FuncName[0] + "." + PatchFuncEntry["name"]
			PatchSection = elf.get_section_by_name(".text." + SymbolName.lower())
			PatchFuncEntry["size"] = PatchSection.data_size

			PatchFuncEntry["alignment"] = 0
			ElfData["PatchFuncs"].append(PatchFuncEntry)

		elif (type(Symbol.entry.st_shndx) == int) and elf.get_section(Symbol.entry.st_shndx).name.startswith(".text.sub.") and Symbol.entry.st_size:
			#this is a special entry, it isn't a function being hooked but is used to break up where code is placed

			#add a known symbol
			ElfData["DefinedSymbols"].append(Symbol.name)

			#get the section, if it isn't already in the list then add it
			Section = elf.get_section(Symbol.entry.st_shndx)
			if Section.name not in AddedSections:
				AddedSections.append(Section.name)

				#add in an entry for this section
				PatchFuncEntry = dict()
				PatchFuncEntry["type"] = "PLACED"
				PatchFuncEntry["name"] = Section.name
				PatchFuncEntry["size"] = Section.data_size
				PatchFuncEntry["address"] = -1
				PatchFuncEntry["kallsyms"] = 0
				PatchFuncEntry["alignment"] = 0
				ElfData["PatchFuncs"].append(PatchFuncEntry)

		elif (type(Symbol.entry.st_shndx) == int) and len(Symbol.name) and (Symbol.entry.st_info.bind == "STB_GLOBAL"):
			#add a known symbol
			ElfData["DefinedSymbols"].append(Symbol.name)

	#symbols are handled, calculate how much space is required for data and normal .text
	for Entry in xrange(0, elf.num_sections()):
		Section = elf.get_section(Entry)
		if Section.name.startswith(".text"):
			if Section.name not in AddedSections:
				ElfData["TextSize"] += Section.data_size
		elif Section.name.startswith(".rodata"):
			ElfData["RODataSize"] += Section.data_size
		elif Section.name.startswith(".data"):
			ElfData["DataSize"] += Section.data_size

	f.close()

	#return what we require
	return ElfData

def CreateWhiteListData(kallsyms, whitelist, PatchList):
	WhiteListData = {"t": [], "d": []}
	whitelist = open(whitelist, "r").read().split("\n")

	#generate a list of patch names
	PatchNames = map(lambda x: x["name"], PatchList)

	#add all entries we have
	for CurEntry in whitelist:
		#skip comments and blank lines
		if (len(CurEntry) == 0) or (CurEntry[0] == "#"):
			continue

		#split up and see if there is a name or address
		#if no size then add a default 0 size
		EntryData = CurEntry.split()

		#if the entry is in the patch names then ignore it
		if EntryData[0] in PatchNames:
			continue

		#get address and size
		EntryAddress = -1
		EntrySize = 0
		EntryType = "t"
		try:
			EntryAddress = int(EntryData[0], 16)

		except:
			#must be a name, see if it is in kallsyms
			if EntryData[0] in kallsyms:
				EntryAddress = kallsyms[EntryData[0]]["address"]
				EntrySize = kallsyms[EntryData[0]]["size"]
				EntryType = kallsyms[EntryData[0]]["type"].lower()

		#if we don't have an actual address then skip the entry
		if EntryAddress == -1:
			continue

		#if we have a 2nd field for the EntryData then get the size it specifies
		if len(EntryData) >= 2:
			try:
				EntrySize = int(EntryData[1], 16)
			except:
				if len(EntryData) == 2:
					#this may be text/data
					EntryType = EntryData[1][0].lower()
				else:
					print "Whitelist entry invalid: %s" % (CurEntry)
					return -1

		#if a 3rd value exists in the whitelist then use that as the type
		if len(EntryData) >= 3:
			EntryType = EntryData[2][0].lower()

		#default to text/code, if not a t then assume it is data
		if EntryType != "t":
			EntryType = "d"

		WhiteListData[EntryType].append({"address": EntryAddress, "size": EntrySize})

	#sort all entries by address
	for Entry in WhiteListData:
		WhiteListData[Entry] = sorted(WhiteListData[Entry], key=lambda val: val["address"])

	#now start combining entries so that everything is contiguous
	for Entry in WhiteListData:
		NewEntryList = []
		WorkingEntry = None
		EndAddress = -1
		for CurEntry in WhiteListData[Entry]:
			#if the end of the last one doesn't match up to this one add a new entry
			if EndAddress != CurEntry["address"]:
				NewEntryList.append(CurEntry)
				EndAddress = CurEntry["address"] + CurEntry["size"]
				WorkingEntry = CurEntry
			else:
				#they line up, combine
				WorkingEntry["size"] += CurEntry["size"]
				EndAddress += CurEntry["size"]

		#rewrite the list with the new combined entries
		WhiteListData[Entry] = NewEntryList

	for Entry in WhiteListData:
		if Entry == "d":
			EntryType = "DATA"
		else:
			EntryType = "TEXT"
		for SubEntry in WhiteListData[Entry]:
			print "%s: 0x%x bytes available at 0x%x" % (EntryType, SubEntry["size"], SubEntry["address"])

	return WhiteListData

def FindPatchLocation(Arch, Whitelist, PatchEntry, Config):
	#this function will modify the whitelist

	#if the patch entry name is data then try the data segment first
	BestEntry = None

	PatchEntry["PatchHeaderSize"] = 0
	if PatchEntry["type"] == "HOOKBEFORE":
		PatchEntry["PatchHeaderSize"] = architectures.arch[Arch].GetPatchBeforeHeaderSize(Config)
	elif PatchEntry["type"] == "HOOKAFTER":
		PatchEntry["PatchHeaderSize"] = architectures.arch[Arch].GetPatchAfterHeaderSize(Config)

	#see how much to offset by if there is alignment
	Offset = 0
	BestEntryOffset = 0
	if PatchEntry["name"] == "DATA":
		#find an entry that is big enough but not too big for the data
		for Entry in Whitelist["d"]:
			if (Entry["size"] >= PatchEntry["size"]) and ((not BestEntry) or (BestEntry["size"] > Entry["size"])):
				#confirm everything is true if we adjust the BestEntry address to our alignment
				if PatchEntry["alignment"]:
					Offset = Entry["address"] & (PatchEntry["alignment"] - 1)
					if(Offset):
						Offset = PatchEntry["alignment"] - Offset

					#if with alignment we won't fit then skip						
					if (Entry["size"] + Offset) < PatchEntry["size"]:
						continue

				#set it
				BestEntry = Entry
				BestEntryOffset = Offset

	if not BestEntry:
		#look through the text area for a spot that is big enough but not too big
		for Entry in Whitelist["t"]:
			if (Entry["size"] >= (PatchEntry["size"] + PatchEntry["PatchHeaderSize"])) and ((not BestEntry) or (BestEntry["size"] > Entry["size"])):
				#confirm everything is true if we adjust the BestEntry address to our alignment
				if PatchEntry["alignment"]:
					Offset = Entry["address"] & (PatchEntry["alignment"] - 1)
					if(Offset):
						Offset = PatchEntry["alignment"] - Offset

					#if with alignment we won't fit then skip
					if (Entry["size"] + Offset) < (PatchEntry["size"] + PatchEntry["PatchHeaderSize"]):
						continue

				#set it
				BestEntry = Entry
				BestEntryOffset = Offset

	#if we found an entry then adjust the white list and return properly
	if BestEntry:
		PatchEntry["address"] = BestEntry["address"] + BestEntryOffset
		BestEntry["size"] -= (PatchEntry["size"] + BestEntryOffset + PatchEntry["PatchHeaderSize"])
		BestEntry["address"] += PatchEntry["size"] + BestEntryOffset + PatchEntry["PatchHeaderSize"]

		#keep everything 4 byte aligned
		BestEntry["size"] &= ~3
		BestEntry["address"] = (BestEntry["address"] + 3) & ~3

		return 0

	#failed to locate an entry
	return -1

def main():
	params = parser.parse_args()

	#get symbols
	AllSymbols = GetSymbols(params.kallsyms)

	#process all objects
	NeededData = []
	PatchFuncs = []
	DefinedSymbols = []
	ExternalSymbols = []
	TotalTextSize = 0
	TotalDataSize = 0
	TotalRODataSize = 0
	TotalBSSSize = 0
	for File in params.objectfiles:
		if File[-2:] == ".o":
			#collect info about each object file
			ElfData = GetObjectData(File, AllSymbols)
			NeededData += ElfData["NeededData"]
			PatchFuncs += ElfData["PatchFuncs"]
			TotalTextSize += ElfData["TextSize"]
			TotalDataSize += ElfData["DataSize"]
			TotalRODataSize += ElfData["RODataSize"]
			TotalBSSSize += ElfData["BSSSize"]
			ExternalSymbols += ElfData["ExternalSymbols"]
			DefinedSymbols += ElfData["DefinedSymbols"]

	#get all the unique entries
	NeededData = list(set(NeededData))
	print "Generating data entries for %d kernel references" % (len(NeededData))

	LoaderScript = ""
	for Entry in NeededData:
		LoaderScript += "%s = 0x%x;\n" % (Entry, AllSymbols[Entry]["address"])

	#get unique entries for Defined and External, then remove all defined from external
	#the list left should give a rough size for the GOT table
	ExternalSymbols = list(set(ExternalSymbols))
	DefinedSymbols = list(set(DefinedSymbols))
	PossibleGOTCount = len([x for x in ExternalSymbols if x not in DefinedSymbols])

	print "Max GOT count: %d" % (PossibleGOTCount)

	#add TotalDataSize together with rounding for alignment
	TotalRODataSize = (TotalRODataSize + 15) & ~15
	TotalDataSize = (TotalDataSize + 15) & ~15
	TotalBSSSize = (TotalBSSSize + 15) & ~15
	TotalGOTSize = ((PossibleGOTCount * 8) + 15) & ~15

	#add in our size for the .offset section
	TotalDataSize += 0x10

	#add the data entries and text entry for common stuff
	#we break out RO seperate so that we can shrink what size of the data area needs the memory protections
	#changed on and helps spread our data out if there are limited insertion points
	PatchFuncs.append({"type": "DATA", "size": TotalTextSize, "name": "TEXT", "address": -1, "kallsyms": 0, "alignment": 0})
	PatchFuncs.append({"type": "DATA", "size": TotalRODataSize, "name": "RODATA", "address": -1, "kallsyms": 0, "alignment": 16})	
	PatchFuncs.append({"type": "DATA", "size": TotalDataSize + TotalBSSSize + TotalGOTSize, "name": "DATA", "address": -1, "kallsyms": 0, "alignment": 16})

	#sort the patch list based on size
	PatchFuncs = sorted(PatchFuncs, key=lambda entry: entry["size"], reverse=True)

	print "Generating data for %d patch locations" % (len(PatchFuncs))

	#grab a whitelist of functions to overwrite in the kernel
	Whitelist = CreateWhiteListData(AllSymbols, params.whitelist, PatchFuncs)
	if type(Whitelist) == int:
		return -1

	#go through each entry
	for PatchEntry in PatchFuncs:
		#if the original function doesn't exist then error
		if PatchEntry["kallsyms"] and (PatchEntry["name"] not in AllSymbols):
			print "Error locating %s to patch" % (PatchEntry["name"])
			return -1

		#fill in entries and remove them from the white list
		if FindPatchLocation(params.arch, Whitelist, PatchEntry, params.config):
			print "Error finding location to insert patch for %s of 0x%x bytes" % (PatchEntry["name"], PatchEntry["size"])
			return -1

		HeaderInfo = ""
		if PatchEntry["PatchHeaderSize"]:
			HeaderInfo = ", header size: 0x%x" % (PatchEntry["PatchHeaderSize"])
		print "%s new location is 0x%x to 0x%x%s" % (PatchEntry["name"], PatchEntry["address"] + PatchEntry["PatchHeaderSize"], PatchEntry["address"] + PatchEntry["size"] + PatchEntry["PatchHeaderSize"], HeaderInfo)

	#now sort based on address
	PatchFuncs = sorted(PatchFuncs, key=lambda entry: entry["address"])

	LoaderScript += """
		SECTIONS
		{
		"""

	for PatchEntry in PatchFuncs:
		if (PatchEntry["type"] == "DATA") and (PatchEntry["name"] == "RODATA"):
			LoaderScript += """
			. = 0x%x;
			.rodata BLOCK(0x10) : { *(.rodata) }
			""" % (PatchEntry["address"])		
		elif (PatchEntry["type"] == "DATA") and (PatchEntry["name"] == "DATA"):
			LoaderScript += """
			. = 0x%x;
			.data BLOCK(0x10) : {
				*(.data)
			}
			.got BLOCK(0x10) : {
				*(.got)
				gotcheck = .;
				QUAD(0)
			}
			.bss BLOCK (0x10) : {
				*(.bss)
			}
			.dataend : {}
			datastart = ADDR(.data);
			datasize = ADDR(.dataend) - ADDR(.data) + 0x%x;
			gotstart = ADDR(.got);
			gotend = ADDR(.got) + SIZEOF(.got);

			""" % (PatchEntry["address"], TotalBSSSize)
		elif (PatchEntry["type"] == "DATA") and (PatchEntry["name"] == "TEXT"):
			LoaderScript += ". = 0x%x;\n.text BLOCK(1) : { *(.text) }\n" % (PatchEntry["address"])
		else:
			#if a hook before/after then modify the section name
			if PatchEntry["type"] == "HOOKBEFORE":
				Type = "before."
			elif PatchEntry["type"] == "HOOKAFTER":
				Type = "after."
			else:
				Type = ""
			LoaderScript += ". = 0x%x;\n.text.%s%s BLOCK(1) : { *(.text.%s%s) }\n" % (PatchEntry["address"] + PatchEntry["PatchHeaderSize"], Type, PatchEntry["name"], Type, PatchEntry["name"])

	#finish script
	LoaderScript += "}"

	#write it out
	open(params.subfolder + "/my_loader.lds", "w").write(LoaderScript)
	return 0

if __name__ == "__main__":
	sys.exit(main())
