# Patchwerk
This program allows for patching C code into compiled, uncompressed linux kernels. Future versions will provide support for additional architectures.

## Usage

### Name
```
  patch_kernel.py
```
  
### Synopsis
```
  patch-kernel.py [-h] -A {aarch64} -i KERNEL_IMAGE [-o OUTPUT]
                       [-p PATCH] [-c] [-s CONFIG] -w WHITELIST [-kallsyms]
                       [--clean]
```

### Options
```
  -h, --help       show this help message and exit
  -A {aarch64}     Architecture to patch
  -i KERNEL_IMAGE  Kernel image
  -o OUTPUT        Output file of modified kernel
  -p PATCH         Folder holding patch code
  -c               Compile only, do not write image
  -s CONFIG        Makefile config file for compiling (default <arch>.config)
  -w WHITELIST     Whitelist for kernel image of functions that can be
                   overwritten
  -kallsyms        Extract just kallsyms
  --clean          Make clean before compiling
```

### Description
patch_kernel.py takes in as an argument a kernel image, a path to a directory containing code for a patch, the architecture of the kernel specified, and a whitelist of functions present in the kernel which are allowed to be modified by patch code.

### General Overview:
This program will first read in the provided kernel and use the kallsyms python script specific to the designated architecture located in the tools directory to extract the symbol table of the kernel image. It will then run the prewritten makefile in required_files to compile any C or assembly source code present in the patch folder and architecture-specific folder, and link it all so that symbols will be resolved. The program will then write a copy of the kernel image containing all hooks for the patched code, the compiled patch binary and data.

## License
   Copyright 2019 Battelle Memorial Institute

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
