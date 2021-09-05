#!/usr/bin/python3
from os.path import join, abspath, exists
from sys import exit
from subprocess import call, check_output
from os import listdir
from platform import system
from math import ceil
from multiprocessing import cpu_count
import shutil

from util import *

# platforms
HOST = system()
assert HOST in ("Linux", "Darwin")

# paths
PATH_ROOT = abspath(join(__file__, "..", ".."))

PATH_DEPS = join(PATH_ROOT, "deps")
PATH_LLVM = join(PATH_ROOT, "llvm")
PATH_PASS = join(PATH_ROOT, "pass")
PATH_TEST = join(PATH_ROOT, "unit")

PATH_CODE = join(PATH_ROOT, "code")
PATH_LOGS = join(PATH_CODE, "logs")
PATH_OUTS = join(PATH_CODE, "outs")
PATH_SRCS = join(PATH_CODE, "srcs")
PATH_OBJS = join(PATH_CODE, "objs")
PATH_BINS = join(PATH_CODE, "bins")
PATH_EXTS = join(PATH_CODE, "exts")
PATH_BCFS = join(PATH_CODE, "bcfs")
PATH_MODS = join(PATH_CODE, "mods")
PATH_TRAS = join(PATH_CODE, "tras")
PATH_SYMS = join(PATH_CODE, "syms")

PATH_WORK = join(PATH_ROOT, "work")


# deps
DEPS_PEX = join(PATH_DEPS,"pex")
DEPS_FMT = join(PATH_DEPS,"fmt")
DEPS_Z3 = join(PATH_DEPS, "z3")
DEPS_UTIL = join(PATH_DEPS, "util")
DEPS_PRINTFUNC = join(PATH_DEPS, "print_func")
PATH_ENTRY = join(PATH_DEPS,"entry_analysis")
PATH_CALLCHAIN = join(PATH_DEPS,"callchain")
PATH_TAINT = join(PATH_DEPS,"taintSummary")
#taint analysis
PATH_TAINT_SO = join(PATH_TAINT,"build","SoundyAliasAnalysis","libSoundyAliasAnalysis.so")
#entry analysis
PATH_ENTRY_EXE = join(PATH_ENTRY,"build","entry_analysis")
#entry callchain
PATH_CALLCHAIN_SO = join(PATH_CALLCHAIN,"build","SoundyAliasAnalysis","libSoundyAliasAnalysis.so")
#call graph generation tool
PATH_PEX_EXE = join(DEPS_PEX,"exe.sh")
PATH_PEX_SO = join(DEPS_PEX,"build","gatlin","libgatlin.so")
# print_func
PATH_PRINTFUNC = join(DEPS_PRINTFUNC,"build", "print_func")
# pass
PASS_BDIR = join(PATH_PASS, "build")
PASS_KSYM = join(PASS_BDIR, "KSym", "KSym.so")

# llvm-9.0
LLVM_PREP = join(PATH_LLVM, "kubo-bins-9.0","build")
LLVM_PRE_PREP = join(PATH_LLVM,"bins-9.0")
#LLVM_PREP = join(PATH_LLVM,"bins-9.0")

LLVM_BINS = join(LLVM_PREP,"bin")
LLVM_BIN_CPP = join(LLVM_BINS, "clang-cpp")
LLVM_BIN_CLA = join(LLVM_BINS, "clang")
LLVM_BIN_CATCH_USER = join(LLVM_BINS, "catch__user")
LLVM_BIN_CXX = join(LLVM_BINS, "clang++")
LLVM_BIN_LLD = join(LLVM_BINS, "ld.lld")
LLVM_BIN_BLD = join(LLVM_BINS, "llvm-link")
LLVM_BIN_OPT = join(LLVM_BINS, "opt")
LLVM_BIN_DIS = join(LLVM_BINS, "llvm-dis")
LLVM_BIN_AS = join(LLVM_BINS, "llvm-as")

LLVM_PRE_BINS = join(LLVM_PRE_PREP,"bin")
LLVM_PRE_BIN_CPP = join(LLVM_PRE_BINS, "clang-cpp")
LLVM_PRE_BIN_CLA = join(LLVM_PRE_BINS, "clang")
LLVM_PRE_BIN_CXX = join(LLVM_PRE_BINS, "clang++")
LLVM_PRE_BIN_LLD = join(LLVM_PRE_BINS, "ld.lld")
LLVM_PRE_BIN_BLD = join(LLVM_PRE_BINS, "llvm-link")
LLVM_PRE_BIN_OPT = join(LLVM_PRE_BINS, "opt")
LLVM_PRE_BIN_DIS = join(LLVM_PRE_BINS, "llvm-dis")
LLVM_PRE_BIN_AS = join(LLVM_PRE_BINS, "llvm-as")

LLVM_SYMS = join(PATH_LLVM, "syms")

TRANS_FLAGS = ["-std-link-opts", "-O2","-verify"]

# Change the app root and source directory.
app_root = join(PATH_ROOT, "code/srcs/se-stable-5.4.1")
source = join(PATH_ROOT, "code/srcs/main.c") # 

def shell(cmdstr):
    call(cmdstr, shell = True, stdout=None, stderr = None)

def ir_gen():
    print("== IR GENERATION")
    out = join(app_root, "target.bc")
    ubsan_params = "-fsanitize=signed-integer-overflow,unsigned-integer-overflow,shift-exponent,integer-divide-by-zero,implicit-unsigned-integer-truncation,implicit-signed-integer-truncation,implicit-integer-sign-change,vla-bound,array-bounds,local-bounds"
    cmdstr = "%s %s -emit-llvm -O2 -c %s -o %s" % (LLVM_BIN_CLA, ubsan_params, source, out)
    shell(cmdstr)

    source_kubo = source[:-2] +'-kubo'+source[-2:]
    with open(source,'r') as rf:
        with open(source_kubo,'w') as wf:
            wf.write('''#define __user __attribute__((noderef))\n\n''')
            wf.write(rf.read())

    out_2 = join(app_root, "built-in.static")
    cmdstr = "%s %s -- %s" % (LLVM_BIN_CATCH_USER, source_kubo, out_2)
    shell(cmdstr)
    kubofile = join(app_root, "built-in_kubo.txt")
    shutil.copyfile(out_2, kubofile)

def trans():
    print("== TRANS")
    inf = join(app_root, "target.bc")
    out = join(app_root, "built-in.ll")
    red = join(app_root, "red.trans")
    cmdstr = "%s %s %s > %s" % (LLVM_BIN_OPT, " ".join(TRANS_FLAGS), inf, out)
    shell(cmdstr)

def cg_gen():
    print("== CALL GRAPH GENERATION")
    inputfile = join(app_root, "built-in.ll")
    cgfile = join(app_root, "cg_pex.txt")
    cmdstr = "%s %s %s %s %s" %(PATH_PEX_EXE, LLVM_PRE_BIN_OPT, PATH_PEX_SO, inputfile, cgfile)
    shell(cmdstr)

def entry_ana():
    print("== ENTRY ANNOTATION")
    inputfile = join(app_root, "built-in.ll")
    entryfile = join(app_root, "entry.txt")
    cmdstr = "%s %s %s" % (PATH_ENTRY_EXE, inputfile, entryfile)
    shell(cmdstr)


def taint_ana():
    print("== TAINT ANNOTATION")
    inputfile = join(app_root, "built-in.ll")
    entryfile = join(app_root, "entry.txt")
    taintfile = join(app_root, "taint.txt")
    cgfile = join(app_root, "cg_pex.txt")
    cmdstr = "%s -load %s -dr_checker -callgraphFile=%s -disable-output -outputFile=%s %s" \
            %(LLVM_PRE_BIN_OPT, PATH_TAINT_SO, cgfile, taintfile, inputfile)
    shell(cmdstr)
    return

def ir_gen_dbg():
    print("== IR GENERATION DEBUG")
    out = join(app_root, "target-dbg.bc")
    ubsan_params = "-fsanitize=signed-integer-overflow,unsigned-integer-overflow,shift-exponent,integer-divide-by-zero,implicit-unsigned-integer-truncation,implicit-signed-integer-truncation,implicit-integer-sign-change,vla-bound,array-bounds,local-bounds"
    cmdstr = "%s -g %s -emit-llvm -O2 -c %s -o %s" % (LLVM_BIN_CLA, ubsan_params, source, out)
    shell(cmdstr)

def trans_dbg():
    print("== TRANS DEBUG")
    inf = join(app_root, "target-dbg.bc")
    out = join(app_root, "built-in-dbg.ll")
    cmdstr = "%s %s %s > %s" % (LLVM_BIN_OPT, " ".join(TRANS_FLAGS), inf, out)
    shell(cmdstr)

def run():
    print("== KUBO RUN")
    cgfile = join(app_root, "cg_pex.txt")
    taintfile = join(app_root, "taint.txt")
    entryfile = join(app_root, "entry.txt")
    inputfile = join(app_root, "built-in.ll")
    outfile = join(app_root, "result.txt")
    _userfile = join(app_root, "built-in_kubo.txt")
    errfile = join(app_root, "err.txt")
    cmdstr = "%s -load %s -KSym -cgf %s -outf %s -taintf %s -usrinputf %s -entryf %s \
        -disable-verify -disable-output %s 2> %s" \
        %(LLVM_PRE_BIN_OPT, PASS_KSYM, cgfile, outfile, taintfile, _userfile, entryfile, inputfile, errfile)
    shell(cmdstr)

with envpath("LD_LIBRARY_PATH", resolve(DEPS_Z3, "bins", "lib")):
    ir_gen()
    trans()
    cg_gen()
    entry_ana()
    taint_ana()
    ir_gen_dbg()
    trans_dbg()
    run()
