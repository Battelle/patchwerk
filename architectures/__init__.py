import os
import enum

def __init__():
    global __all__
    global arch

    import sys
    import importlib

    __all__ = []

    arch = dict()

    CurModule = sys.modules[__name__]

    for entry in os.listdir(os.path.dirname(__file__)):
        if os.path.isdir(os.path.dirname(__file__) + "/" + entry):
            __all__.append(entry)
            arch[entry] = importlib.import_module("architectures." + entry)
            arch[entry].architectures = CurModule

def RecompileIfChanged(Arch, Config, Filename):
    #see if the input file is different than the output file, if so then recompile it via make
    Recompile = False

    CurPath = os.path.dirname(os.path.abspath(__file__))
    if os.path.isfile("%s/%s/patches/patch_%s.bin" % (CurPath, Arch, Filename)) == False:
        Recompile = True

    elif not os.path.isfile("%s/%s/patches/patch_%s.S" % (CurPath, Arch, Filename)):
        print "Error finding %s/patches/patch_%s.S" % (Arch, Filename)
        return -1

    else:
        InStat = os.stat("%s/%s/patches/patch_%s.S" % (CurPath, Arch, Filename))
        OutStat = os.stat("%s/%s/patches/patch_%s.bin" % (CurPath, Arch, Filename))

        #if our time is newer then recompile
        if InStat.st_mtime > OutStat.st_mtime:
            Recompile = True
            os.unlink("%s/%s/patches/patch_%s.bin" % (CurPath, Arch, Filename))

    #if we need to recompile then do so
    if Recompile:
        import subprocess
        s = subprocess.Popen(["make", "-C", "%s/%s/patches" % (CurPath, Arch), "INCLUDE=" + Config, "NAME=" + Filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ret = s.wait()

        if (ret != 0) or (not os.path.isfile("%s/%s/patches/patch_%s.bin" % (CurPath, Arch, Filename))):
            print "Error compiling %s/patches/patch_%s.bin" % (Arch, Filename)
            stdoutdata, stderrdata = s.communicate()
            print("STDOUT:\n{}\n\nSTDERR:{}\n".format(stdoutdata, stderrdata))
            return -1

    return 0

__init__()
