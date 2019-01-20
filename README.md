# clakerbu

[![License](https://img.shields.io/github/license/angr/angr.svg)](https://github.com/ucsb-seclab/difuze/blob/master/LICENSE)

Tool to get cumulative LLVM bitcode files for kernel drivers for architectures `arm32` and `aarch64`.

This tool helps you get cumulative bitcode files for each of the kernel drivers. This is helpful for any instrumentation tasks based on `LLVM`. For instance, You can use this tool to build the bitcode file for a driver, perform instrumentation, convert it back to object file, and then use the `make` to create the kernel with the instrumented driver.

## Note
This only works for `arm32` or `aarch64` architectures.

## Dependencies
* Install [Bear](https://github.com/Machiry/Bear)
* Install [clang and llvm](http://releases.llvm.org/)

## How to use:
### Build your kernel.
Run `make` using the following command:
```
bear make
```
The above command will create `compile_commands.json` in the current directory.

### Running
```
usage: clakerbu.py [-h] -l LLVM_BC_OUT -k KERNEL_SRC_DIR -m COMPILE_JSON -n
                   ARCH_NUM

optional arguments:
  -h, --help         show this help message and exit
  -l LLVM_BC_OUT     Destination directory where all the generated bitcode
                     files should be stored.
  -k KERNEL_SRC_DIR  Base directory of the kernel sources.
  -m COMPILE_JSON    Path to the json file generated by Bear.
  -n ARCH_NUM        Destination architecture, 32 bit (1) or 64 bit (2).
```
Example for `aarch64:
```
cd clakerbu/
python clakerbu.py -l /llvm_bitcode_out -k <PATH_WHERE_YOU_RAN_MAKE> -m <PATH_TO_THE_COMPILE_COMMANDS_JSON_CREATED_ABOVE> -n 2
```

The driver bitcode files will be present in the folder `<LLVM_BC_OUT>` with extension `final.linked.bc` along with other intermediate files.

The kernel modules end with `..final.linked.bc` i.e., if you find `iproc-rng200..final.linked.bc`, that means it is the bitcode file for `iproc-rng200.ko` from the kernel build.


### Shoutouts
* [rizsotto](https://github.com/rizsotto) for the amazing Bear tool.
