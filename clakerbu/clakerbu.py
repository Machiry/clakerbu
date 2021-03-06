import argparse
from compile_json_parser import parse_compile_json
from build_llvm import build_drivers
from log_stuff import *
import sys
import subprocess
import os


def setup_args():
    parser = argparse.ArgumentParser()

    required_named = parser

    required_named.add_argument('-l', action='store', dest='llvm_bc_out',
                                help='Destination directory where all the generated bitcode files should be stored.',
                                required=True)

    required_named.add_argument('-k', action='store', dest='kernel_src_dir',
                                help='Base directory of the kernel sources.', required=True)

    required_named.add_argument('-m', action='store', dest='compile_json',
                                help='Path to the json file generated by Bear.', required=True)

    required_named.add_argument('-n', action='store', dest='arch_num',
                                help='Destination architecture, 32 bit (1) or 64 bit (2).', type=int,
                                required=True)
    required_named.add_argument('-isclang', action='store_true', dest='is_clang_build',
                                help='flag to indicate that clang was used to built the kernel')

    required_named.add_argument('-clangp', action='store', dest='clang_path',
                                help='Absolute path to the clang binary (if not provided, the one '
                                     'available in the path will be used)',
                                default=get_bin_path("clang"))

    required_named.add_argument('-llvmlinkp', action='store', dest='llvmlink_path',
                                help='Absolute path to the llvm-link binary (if not provided, the one '
                                     'available in the path will be used)',
                                default=get_bin_path("llvm-link"))

    return parser


def get_bin_path(bin_name):
    out_p = subprocess.check_output('which ' + bin_name, shell=True)
    return out_p.strip()


def main():
    arg_parser = setup_args()
    parsed_args = arg_parser.parse_args()
    clang_path = parsed_args.clang_path
    llvm_link_path = parsed_args.llvmlink_path
    if (not os.path.exists(clang_path)) or (not os.path.exists(llvm_link_path)):
        log_error("clang or llvm-link not available in the system path.")
        sys.exit(-1)
    # get all the compilation and linker commands.
    compile_commands, linker_commands = parse_compile_json(parsed_args.compile_json)
    os.system("mkdir -p " + parsed_args.llvm_bc_out)
    # build everything.
    build_drivers(compile_commands, linker_commands, parsed_args.kernel_src_dir, parsed_args.arch_num,
                  clang_path, llvm_link_path, parsed_args.llvm_bc_out, parsed_args.is_clang_build)


if __name__ == "__main__":
    main()
