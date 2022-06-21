#!/usr/bin/python3
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_LITTLE_ENDIAN, x86

from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS

__MAX_NUM_INS = 40
MAX_INS_SIZE = 8

TARGET_CHUNK_SIZE = 0x1000
CODE_CHUNK_SIZE = 2 * TARGET_CHUNK_SIZE
INITIAL_SOURCES = [
            #  (x86.X86_REG_R12, (0x20, 0x70)), # REG, (min disp, max disp)
            #  (x86.X86_REG_R12, (0x20, 0x1020)), # REG, (min disp, max disp)
            (x86.X86_REG_R14, (0x8, 0x108)), # REG, (min disp, max disp)
            #  (x86.X86_REG_R13, (0x8, 0x108)), # REG, (min disp, max disp)
            #  (x86.X86_REG_R9, (0x0, 0x60)), # REG, (min disp, max disp)
            #  (x86.X86_REG_R15, (0x0, 0x60)), # REG, (min disp, max disp)
            #  (x86.X86_REG_RBX, (0x20, 0x100)), # REG, (min disp, max disp)
]

md = Cs(CS_ARCH_X86, CS_MODE_64 + CS_MODE_LITTLE_ENDIAN)
md.detail = True

TARGET_REGS = [
    x86.X86_REG_RDI, x86.X86_REG_RSI, x86.X86_REG_RDX, x86.X86_REG_RCX,
    x86.X86_REG_R8, x86.X86_REG_R9
]

TARGET_INS_SHIFT = [x86.X86_INS_SHL, x86.X86_INS_SAL]
TARGET_INS_MUL = [x86.X86_INS_MUL]

TARGET_MIN_SHIFT = 6
TARGET_MIN_MUL = 1 << TARGET_MIN_SHIFT

ALL_REG64 = [
    x86.X86_REG_R8, x86.X86_REG_R9, x86.X86_REG_R10, x86.X86_REG_R11,
    x86.X86_REG_R12, x86.X86_REG_R13, x86.X86_REG_R14, x86.X86_REG_R15,
    x86.X86_REG_RAX, x86.X86_REG_RBX, x86.X86_REG_RCX, x86.X86_REG_RDX,
    x86.X86_REG_RDI, x86.X86_REG_RSI, x86.X86_REG_RBP
]

# these regs we can leak to without needing any shr
LEAK16_REGS = [
    x86.X86_REG_R8W,  x86.X86_REG_R9W,  x86.X86_REG_R10W, x86.X86_REG_R11W,
    x86.X86_REG_R12W, x86.X86_REG_R13W, x86.X86_REG_R14W, x86.X86_REG_R15W,
    x86.X86_REG_AH,   x86.X86_REG_AX,   x86.X86_REG_BX,   x86.X86_REG_BH,
    x86.X86_REG_CH,   x86.X86_REG_CX,   x86.X86_REG_DX,
    x86.X86_REG_DH,   x86.X86_REG_DI,   x86.X86_REG_SI, x86.X86_REG_BP
]

LEAK8_REGS = [
    x86.X86_REG_R8B,  x86.X86_REG_R9B,  x86.X86_REG_R10B, x86.X86_REG_R11B,
    x86.X86_REG_R12B, x86.X86_REG_R13B, x86.X86_REG_R14B, x86.X86_REG_R15B,
    x86.X86_REG_AL,   x86.X86_REG_BL,
    x86.X86_REG_CL,   x86.X86_REG_DL, x86.X86_REG_DIL,   x86.X86_REG_SIL, x86.X86_REG_BPL
]

# 32 bit registers need minimum 11bit shr OR AND < 0xfffff
LEAK32_REGS = [
    x86.X86_REG_R8D,   x86.X86_REG_R9W,  x86.X86_REG_R10W, x86.X86_REG_R11W,
    x86.X86_REG_R12D,  x86.X86_REG_R13W, x86.X86_REG_R14W, x86.X86_REG_R15W,
    x86.X86_REG_EAX,   x86.X86_REG_EBX,  x86.X86_REG_ECX,  x86.X86_REG_EDX,
    x86.X86_REG_EDI,   x86.X86_REG_ESI, x86.X86_REG_EBP
]

# 64 bit registers need minimum 43bit shr AND < 0xfffff


# rakes a reg gives all regs that work on this reg
def reg2regs(reg):
    regs = []
    if reg == 0:
        return []
    elif (reg in [x86.X86_REG_AL, x86.X86_REG_AH, x86.X86_REG_AX, x86.X86_REG_EAX, x86.X86_REG_RAX]):
        regs.append(x86.X86_REG_AL)
        regs.append(x86.X86_REG_AH)
        regs.append(x86.X86_REG_AX)
        regs.append(x86.X86_REG_EAX)
        regs.append(x86.X86_REG_RAX)
    elif (reg in [x86.X86_REG_BL, x86.X86_REG_BH, x86.X86_REG_BX, x86.X86_REG_EBX, x86.X86_REG_RBX]):
        regs.append(x86.X86_REG_BL)
        regs.append(x86.X86_REG_BH)
        regs.append(x86.X86_REG_BX)
        regs.append(x86.X86_REG_EBX)
        regs.append(x86.X86_REG_RBX)
    elif (reg in [x86.X86_REG_CL, x86.X86_REG_CH, x86.X86_REG_CX, x86.X86_REG_ECX, x86.X86_REG_RCX]):
        regs.append(x86.X86_REG_CL)
        regs.append(x86.X86_REG_CH)
        regs.append(x86.X86_REG_CX)
        regs.append(x86.X86_REG_ECX)
        regs.append(x86.X86_REG_RCX)
    elif (reg in [x86.X86_REG_DL, x86.X86_REG_DH, x86.X86_REG_DX, x86.X86_REG_EDX, x86.X86_REG_RDX]):
        regs.append(x86.X86_REG_DL)
        regs.append(x86.X86_REG_DH)
        regs.append(x86.X86_REG_DX)
        regs.append(x86.X86_REG_EDX)
        regs.append(x86.X86_REG_RDX)
    elif (reg in [x86.X86_REG_SPL, x86.X86_REG_SP, x86.X86_REG_ESP, x86.X86_REG_RSP]):
        regs.append(x86.X86_REG_SPL)
        regs.append(x86.X86_REG_SP)
        regs.append(x86.X86_REG_ESP)
        regs.append(x86.X86_REG_RSP)
    elif (reg in [x86.X86_REG_BPL, x86.X86_REG_BP, x86.X86_REG_EBP, x86.X86_REG_RBP]):
        regs.append(x86.X86_REG_BPL)
        regs.append(x86.X86_REG_BP)
        regs.append(x86.X86_REG_EBP)
        regs.append(x86.X86_REG_RBP)
    elif (reg in [x86.X86_REG_SIL, x86.X86_REG_SI, x86.X86_REG_ESI, x86.X86_REG_RSI]):
        regs.append(x86.X86_REG_SIL)
        regs.append(x86.X86_REG_SI)
        regs.append(x86.X86_REG_ESI)
        regs.append(x86.X86_REG_RSI)
    elif (reg in [x86.X86_REG_DIL, x86.X86_REG_DI, x86.X86_REG_EDI, x86.X86_REG_RDI]):
        regs.append(x86.X86_REG_DIL)
        regs.append(x86.X86_REG_DI)
        regs.append(x86.X86_REG_EDI)
        regs.append(x86.X86_REG_RDI)
    elif (reg in [x86.X86_REG_R8B, x86.X86_REG_R8W, x86.X86_REG_R8D, x86.X86_REG_R8]):
        regs.append(x86.X86_REG_R8B)
        regs.append(x86.X86_REG_R8W)
        regs.append(x86.X86_REG_R8D)
        regs.append(x86.X86_REG_R8)
    elif (reg in [x86.X86_REG_R9B, x86.X86_REG_R9W, x86.X86_REG_R9D, x86.X86_REG_R9]):
        regs.append(x86.X86_REG_R9B)
        regs.append(x86.X86_REG_R9W)
        regs.append(x86.X86_REG_R9D)
        regs.append(x86.X86_REG_R9)
    elif (reg in [x86.X86_REG_R10B, x86.X86_REG_R10W, x86.X86_REG_R10D, x86.X86_REG_R10]):
        regs.append(x86.X86_REG_R10B)
        regs.append(x86.X86_REG_R10W)
        regs.append(x86.X86_REG_R10D)
        regs.append(x86.X86_REG_R10)
    elif (reg in [x86.X86_REG_R11B, x86.X86_REG_R11W, x86.X86_REG_R11D, x86.X86_REG_R11]):
        regs.append(x86.X86_REG_R11B)
        regs.append(x86.X86_REG_R11W)
        regs.append(x86.X86_REG_R11D)
        regs.append(x86.X86_REG_R11)
    elif (reg in [x86.X86_REG_R12B, x86.X86_REG_R12W, x86.X86_REG_R12D, x86.X86_REG_R12]):
        regs.append(x86.X86_REG_R12B)
        regs.append(x86.X86_REG_R12W)
        regs.append(x86.X86_REG_R12D)
        regs.append(x86.X86_REG_R12)
    elif (reg in [x86.X86_REG_R13B, x86.X86_REG_R13W, x86.X86_REG_R13D, x86.X86_REG_R13]):
        regs.append(x86.X86_REG_R13B)
        regs.append(x86.X86_REG_R13W)
        regs.append(x86.X86_REG_R13D)
        regs.append(x86.X86_REG_R13)
    elif (reg in [x86.X86_REG_R14B, x86.X86_REG_R14W, x86.X86_REG_R14D, x86.X86_REG_R14]):
        regs.append(x86.X86_REG_R14B)
        regs.append(x86.X86_REG_R14W)
        regs.append(x86.X86_REG_R14D)
        regs.append(x86.X86_REG_R14)
    elif (reg in [x86.X86_REG_R15B, x86.X86_REG_R15W, x86.X86_REG_R15D, x86.X86_REG_R15]):
        regs.append(x86.X86_REG_R15B)
        regs.append(x86.X86_REG_R15W)
        regs.append(x86.X86_REG_R15D)
        regs.append(x86.X86_REG_R15)
    else:
        # AH, DH, FPU regs etc
        regs.append(reg)

    return regs


def reg_in(reg, regs):
    if list(set(reg2regs(reg)) & set(regs)):
        return True
    else:
        return False


def reg_eq(reg, reg__):
    return reg_in(reg, reg2regs(reg__))

def insn_is_mov(ins):
    # TODO: bug in this thing, found case with ++ 0x259dda
    return ins.id >= x86.X86_INS_MOV and ins.id <= x86.X86_INS_MOVZX

# math stuff doesn't break things but we need to fix up the displacement it
# caused it the operated on our controlled reg
ARITH_ADD = [x86.X86_INS_ADC, x86.X86_INS_ADD, x86.X86_INS_ADCX]
ARITH_SUB = [x86.X86_INS_SUB, x86.X86_INS_SBB]
ARITH_INS= [
    #  X86_INS_SHR, X86_INS_SHL,
    #  X86_INS_MUL, X86_INS_IMUL, X86_INS_IDIV, X86_INS_DIV,
] + ARITH_ADD + ARITH_SUB

#BasicBlock end (cfg edge)
BB_END = [
    x86.X86_INS_RET, x86.X86_INS_RETF, x86.X86_INS_RETFQ,
    x86.X86_INS_IRET, x86.X86_INS_JAE, x86.X86_INS_JA, x86.X86_INS_JBE,
    x86.X86_INS_JB, x86.X86_INS_JCXZ, x86.X86_INS_JECXZ, x86.X86_INS_JE,
    x86.X86_INS_JGE, x86.X86_INS_JG, x86.X86_INS_JLE, x86.X86_INS_JL,
    x86.X86_INS_JMP, x86.X86_INS_JNE, x86.X86_INS_JNO, x86.X86_INS_JNP, x86.X86_INS_JNS,
    x86.X86_INS_JO, x86.X86_INS_JP, x86.X86_INS_JRCXZ, x86.X86_INS_JS, x86.X86_INS_CALL
]

def insn_ops(ins):
    src = None
    dst = None
    imm = None
    nOps = len(ins.operands)
    if nOps == 1:
        dst = ins.operands[0]
    elif nOps == 2:
        dst, src = ins.operands
    elif nOps == 3:
        dst, src, imm = ins.operands
    return (dst,src,imm)

def intersection(lst1, lst2):
    lst3 = [value for value in lst1 if value in lst2]
    return lst3

# returns the src register that gets overridden
def insn_overrides_srcs(ins, srcs):
    if ins.id in [x86.X86_INS_CMP, x86.X86_INS_TEST]:
        return None
    if ins.id == x86.X86_INS_NEG:
        # will just be a bit annoying to use
        return None
    dst, src, imm = insn_ops(ins)
    if not dst or dst.reg == x86.X86_REG_INVALID:
        return None

    if src and src.type == x86.X86_OP_REG and src.reg in srcs:
        # if reading from a reg, and that reg is in our srcs then dst continues
        # to be a source.
        return None

    for dst_variant in reg2regs(dst.reg):
        if dst_variant in srcs:
            # a src is being overwritten
            return dst_variant # is is being overwritten
    return None

def ins_is_reg_changed(ins, reg):
    if (ins.id >= x86.X86_INS_MOV and ins.id <= x86.X86_INS_MOVZX):
        dest, src = ins.operands
        if (src.type == x86.X86_OP_REG and dest.type == x86.X86_OP_REG):
            if reg_eq(src.reg, reg):
                return dest.reg
    return reg


def op_is_reg(op):
    return (op.type == x86.X86_OP_REG)


def op_is_tmem(op):
    if (op.type == x86.X86_OP_MEM):
        return (reg_in(op.mem.base, TARGET_REGS))
    else:
        return False


def op_is_tmem_index(op, reg):
    if (op.type == x86.X86_OP_MEM):
        return (reg_in(op.mem.base, TARGET_REGS) and reg_eq(op.mem.index, reg))
    else:
        return False


def op_is_tmem_scale(op, reg):
    if (op.type == x86.X86_OP_MEM):
        return (op_is_tmem_index(op, reg) and op.mem.scale >= TARGET_MIN_MUL)
    else:
        return False


def op_is_timm(op, tmin):
    if (op.type == x86.X86_OP_IMM):
        return (op.imm >= tmin)
    else:
        return False

def op_is_vector(op):
    return op.reg > x86.X86_REG_XMM0 and op.reg < x86.X86_REG_YMM31

def _op_has_reg(op, reg):
    return op and op.type == x86.X86_OP_REG and op.reg == reg

# is the op one of the given regs?
def op_has_reg(op, regs):
    return any([_op_has_reg(op, reg) for reg in regs])
    #  return op and op.type == x86.X86_OP_REG and op.reg in regs

def _op_has_mem_reg(op, reg):
    return op and op.type == x86.X86_OP_MEM and (op.mem.base == reg or
                                                 op.mem.index == reg)

# is the op one of the given regs?
def op_has_mem_reg(op, regs):
    return any([_op_has_mem_reg(op,reg) for reg in regs])

INSN_NOT_A_LOAD = [ x86.X86_INS_LEA, x86.X86_INS_CMP ]
zero_regs = []
def is_load_to_reg(ins, valid_dsts, valid_srcs):
    if ins.id in INSN_NOT_A_LOAD:
        return False
    for op in ins.operands:
        if op_is_vector(op):
            return False
    dst,src,x = insn_ops(ins)
    if not src:
        return False
    if not op_has_reg(dst, valid_dsts):
        return False
    if (src.type != x86.X86_OP_MEM):
        return False
    # sib = scale index base
    if (ins.sib != 0 and src.mem.scale != 0 and src.mem.index not in
            zero_regs):
        return False
    for valid_src, (disp_min,disp_max) in valid_srcs:
        if (src.mem.base != valid_src and src.mem.index != valid_src):
            # not valid src
            continue
        if (src.mem.disp < disp_min):
            continue
        if (src.mem.disp > disp_max):
            continue
        return True
    return False

def insn_is_vector(insn):
    for op in insn.operands:
        if op_is_vector(op):
            return True
    return False

# this assumes we're in state LOAD_A_PTR||LOAD_B_PTR
def state_load_ptr(insn, valid_dst, valid_src):
    return is_load_to_reg(insn, valid_dst, valid_src)

def state_load_secret(insn, ptr_regs):
    return is_reg_leak_load(insn, ptr_regs)

def state_leak_op(op, leak_regs, ptr_regs):
    if not op:
        return False
    if not op.type == x86.X86_OP_MEM:
        # operand is not memory, so not possible to be leaky
        return False
    rb_reg = None
    for reg in ptr_regs:
        if reg_in(reg, [op.mem.base, op.mem.index]):
            rb_reg = reg
    if not rb_reg:
        return False
    for reg in leak_regs:
        if reg_in(reg, [op.mem.base, op.mem.index]):
            # our leak_reg is loaded!
            return True
    return False

def state_leak(insn, leak_regs, ptr_regs):
    dst, src, _ = insn_ops(insn)
    if insn.id in INSN_NOT_A_LOAD:
        return False
    if state_leak_op(dst, leak_regs, ptr_regs):
        return dst
    if state_leak_op(src, leak_regs, ptr_regs):
        return src

def ins_is_tload(ins):
    if (len(ins.operands) == 2):
        dest, src = ins.operands
        if (op_is_reg(dest) and op_is_tmem(src)):
            return dest.reg
    return 0

def ins_is_tshift(ins, reg):
    if (ins.id in TARGET_INS_SHIFT and len(ins.operands) == 2):
        dest, src = ins.operands
        if (op_is_reg(dest) and op_is_timm(src, TARGET_MIN_SHIFT)):
            return reg_eq(dest.reg, reg)
    return False

def ins_is_tmul(ins, reg):
    if (ins.id in TARGET_INS_MUL):
        if (len(ins.operands) == 2):
            dest, src = ins.operands
            if op_is_timm(dest, TARGET_MIN_MUL):
                return reg_eq(dest.reg, reg)

        elif (len(ins.operands) == 3):
            dest, x, y = ins.operands
            if (reg_eq(x.reg, reg) and op_is_timm(y, TARGET_MIN_MUL)):
                return reg_eq(dest.reg, reg)

    return False


def ins_is_tindex(ins, reg):
    if (len(ins.operands) == 2):
        dest, src = ins.operands
        if (op_is_reg(dest) and op_is_tmem_index(src, reg)):
            return dest.reg
    return 0


def ins_is_tindex_scale(ins, reg):
    if (len(ins.operands) == 2):
        dest, src = ins.operands
        if (op_is_reg(dest) and op_is_tmem_scale(src, reg)):
            return dest.reg
    return 0


def ins_is_tindex_lea(ins, lea_reg):
    if (ins.id == x86.X86_INS_LEA):
        return 0
    elif (len(ins.operands) == 2):
        dest, src = ins.operands

        if (dest.type != x86.X86_OP_REG):
            return 0

        if (reg_eq(src.mem.base, lea_reg)
                and (src.mem.index == x86.X86_REG_INVALID
                     or reg_in(src.mem.index, TARGET_REGS))):
            return dest.reg
    return 0


def print_ins(offset, ins, descr=""):
    if ins:
        print(hex(offset),
              descr.ljust(5),
              ins.mnemonic.ljust(10),
              ins.op_str.ljust(28),
              ins.bytes.hex(),
              flush=True)
    else:
        print(hex(offset), descr, flush=True)


def print_exit():
    print("\t*gadget*", flush=True)

def commit_load_to_reg(insn, my_dsts, my_srcs, my_ptr_regs, leak_regs):
    # my_srcs are my_src_aliases, so SHOULD update those too..
    dst, src, x = insn_ops(insn)
    disp = src.mem.disp
    # now you are not allowed to load into this register any more.
    my_dsts.remove(dst.reg)
    if dst.reg in leak_regs:
        leak_regs.remove(dst.reg)
    my_ptr_regs.append(dst.reg)
    return
    # removing sources is a bad idea. we lose potential gadgets

    my_new_srcs = []
    for reg,(disp_min,disp_max) in my_srcs:
        # TODO: we dont update aliases. the pointer has now been taken so the
        # next load must not use it.
        if reg != src.mem.base and reg != src.mem.index:
            my_new_srcs.append((reg, (disp_min,disp_max)))
        # same reg
        if disp < disp_min or disp > disp_max:
            my_new_srcs.append((reg, (disp_min,disp_max)))
        # disp in range
        # this needs to be split now
        if disp - disp_min >= 8:
            my_new_srcs.append((reg, (disp_min, disp-1)))
        if disp_max - (disp + 8) >= 8:
            my_new_srcs.append((reg, (disp+8, disp_max)))

        #  if reg == src.mem.index:
    my_srcs.clear()
    for el in my_new_srcs:
        my_srcs.append(el)



def is_reg_load(insn):
    # we want to see that any of the ptr_regs are dereferenced.
    dst, src, x = insn_ops(insn)
    if not dst or dst.type != x86.X86_OP_REG:
        return False
    if not src or src.type != x86.X86_OP_MEM:
        return False
    if insn.id in INSN_NOT_A_LOAD:
        # not a load
        return False
    return True

LEAK_REGS = LEAK8_REGS + LEAK16_REGS + LEAK32_REGS + ALL_REG64

def is_reg_leak_load(insn, my_ptr_regs):
    if not is_reg_load(insn):
        return x86.X86_REG_INVALID
    dst, src, x = insn_ops(insn)
    # does this instruction load from my ptrs?
    if not src.mem.base in my_ptr_regs and not src.mem.index in my_ptr_regs:
        return x86.X86_REG_INVALID
    # this could lead to us overriding our rb ptr dst.reg is in my_ptr_regs
    if (dst.reg not in LEAK_REGS):
        return x86.X86_REG_INVALID
    return dst.reg # leak_reg

def is_rb_load_alt1(insn, my_ptr_regs, leak_regs):
    dst, src, x = insn_ops(insn)
    if dst and (dst.type == x86.X86_OP_MEM and
            (dst.mem.base in my_ptr_regs and dst.mem.index in leak_regs) or
            (dst.mem.base in leak_regs and dst.mem.index in my_ptr_regs)):
        return True
    elif src and (src.type == x86.X86_OP_MEM and
          (src.mem.base in my_ptr_regs and src.mem.index in leak_regs) or
          (src.mem.base in leak_regs and src.mem.index in my_ptr_regs)):
        return True
    return False

def is_dst_rb_ptr_and_leak(insn, my_ptr_regs, leak_regs):
    dst, src, x = insn_ops(insn)
    if insn.id == x86.X86_INS_LEA and op_has_mem_reg(src,  leak_regs ):
        if not dst.reg in leak_regs:
            # propagate leak_reg...
            leak_regs.append(dst.reg)
        return False
    if not ((op_has_reg(src, leak_regs) and op_has_reg(dst, my_ptr_regs)) or
            (op_has_reg(src, my_ptr_regs) and op_has_reg(dst,  leak_regs))):
        return False
    # src is the leak_reg and dst is on of the rb regs
    # or src is one of rb regs and dst is leak_reg
    if insn.id in ARITH_ADD:
        return True
        # dst is rb_ptr + secret
        print("update disp")
        return True
    elif insn.id in ARITH_SUB:
        print("update disp")
        # dst is secret - rb_ptr or rb_ptr - secret
        return True
    return False
    # look for arith add and then normal load.
    # can also be lea of course...

def commit_reg_load(insn, valid_dsts, my_ptr_regs, leak_regs):
    dst, src, x = insn_ops(insn)

    leak_reg = dst.reg

    if not leak_reg in leak_regs:
        leak_regs.append(leak_reg)

    if leak_reg in my_ptr_regs:
        my_ptr_regs.remove(leak_reg)

    # we have used this register for a load, the next load can not use this
    # because that would mean same value is laoded twice.
    # Actually it can still be useful to load it again since it means
    # propagation
    if src.mem.base in my_ptr_regs:
        my_ptr_regs.remove(src.mem.base)
    elif src.mem.index in my_ptr_regs:
        my_ptr_regs.remove(src.mem.index)
    # dst.reg will be the the secret holder
    return dst.reg

def insn_propagates_reg(insn, reg):
    dst, src, x = insn_ops(insn)
    if not src or not dst:
        return False
    if insn.id == x86.X86_INS_LEA and _op_has_mem_reg(src, reg):
        return True
    return _op_has_reg(src, reg)

def insn_propagates_src(insn, my_srcs, my_dsts):
    dst, src, x = insn_ops(insn)
    srcs_regs = [s[0] for s in my_srcs]

    if insn.id == x86.X86_INS_LEA and op_has_mem_reg(src, my_srcs):
        # propagate if lea is used, TODO: fix displacements
        return True

    return (src and src.type == x86.X86_OP_REG and src.reg in srcs_regs and
            dst and dst.type == x86.X86_OP_REG and dst.reg not in srcs_regs and insn_is_mov(insn))

def commit_propagate_src(insn, my_srcs):
    dst, src, x = insn_ops(insn)
    for disp in [s[1] for s in my_srcs if s[0] == src.reg]:
        my_srcs.append((dst.reg, disp))

from enum import Flag, auto

class Needs(Flag):
    # A_PTR is rb_ptr or secret_ptr
    LOAD_A_PTR  = auto()
    # B_PTR is rb_ptr or secret_ptr
    LOAD_B_PTR  = auto()
    # A_PTR or B_PTR deref
    LOAD_SECRET = auto()
    # A_PTR is rb_ptr
    LEAK_A = auto()
    # B_PTR is rb_ptr
    LEAK_B = auto()

def code_search(CODE, base_va):
    for offset in range(0, min(TARGET_CHUNK_SIZE, len(CODE))):
        MAX_NUM_INS = min(__MAX_NUM_INS,
                          int((CODE_CHUNK_SIZE - offset) / MAX_INS_SIZE))
        va = base_va + offset
        __root_ins = list(md.disasm(CODE[offset:], 0, count=1))

        if len(__root_ins) != 1:
            # unable to disassemble from this offset
            continue

        root_ins = __root_ins[0]
        my_srcs = [
        ] + INITIAL_SOURCES
        my_dsts = [reg for reg in ALL_REG64]
        my_ptr_regs = [
            #  x86.X86_REG_RDI,
            #  x86.X86_REG_RSI,
            #  x86.X86_REG_RDX,
            #  x86.X86_REG_RCX,
            #  x86.X86_REG_R8,
            #  x86.X86_REG_R9,
        ] # list of regs

        found = []
        # We need these two ptrs... We can still
        state = 0
        #  state = LOAD_A_PTR | LOAD_B_PTR
        #  state = 0

        if (len(root_ins.operands) != 2):
            # if you dont have two operands it can be a useful root_ins
            continue
        # you are a useful insn if you create more srcs
        leak_regs = []
        if insn_propagates_src(root_ins, my_srcs, my_dsts):
            commit_propagate_src(root_ins, my_srcs)
        elif state_load_ptr(root_ins, my_dsts, my_srcs):
            # load ptr state fulfilled
            #  commit_load_to_reg(root_ins, my_dsts, my_srcs, a_ptr_regs)
            commit_load_to_reg(root_ins, my_dsts, my_srcs, my_ptr_regs,
                               leak_regs)
            #  state &= ~LOAD_A_PTR
            state = 1
            #  print_ins(va, root_ins, '+'*(state))
        else:
            # You may still be useful if you:
            # - change a src disp
            continue
        found.append((va, root_ins))
        va += root_ins.size
        for insn in md.disasm(CODE[offset+root_ins.size:], 0, count=MAX_NUM_INS):
            if (len(found) > 0):
                found.append((va, insn))
            if state < 2 and len(my_srcs) == 0:
                break # bail: all srcs overriden
            if insn.id in BB_END:
                if insn.id == x86.X86_INS_RET: # max byte width
                    if state >= 1:
                        pass
                        #  print_ins(va, insn, "RET")
                break
            if state == 0:
                if is_load_to_reg(insn, my_dsts, my_srcs):
                    state = 1
                    #  print_ins(va, insn, '+'*(state))
                    commit_load_to_reg(insn, my_dsts, my_srcs, my_ptr_regs,
                                       leak_regs)
                    va += insn.size
                    continue
            if state == 3:
                if state_leak(insn, leak_regs, my_ptr_regs):
                    # ok
                    state = 4
                    print("---- Gadget found ----")
                    for (va, insn) in found:
                        print_ins(va, insn, '+'*(state))
                    exit(0)
                for reg in [rs for sublist in [reg2regs(x) for x in leak_regs]
                            for rs in sublist]:
                    # leak_regs... i mean.. they have to be 64 bit.
                    if insn_propagates_reg(insn, reg):
                        # oh, so insn copies reg somewhere
                        dst = insn.operands[0]
                        if dst.type == x86.X86_OP_MEM:
                            # not supporting secret in memory (that isnt rb)
                            pass
                        if dst.type == x86.X86_OP_REG:
                            if not dst.reg in leak_regs:
                                leak_regs.append(dst.reg)
            if state >= 2:
                if state_load_secret(insn, my_ptr_regs): # max byte width
                    state = max(state, 3)
                    print_ins(va, insn, "load sec"+'+'*(state))
                    #  print_ins(va, insn, "load sec"+'+'*(state))
                    # the src can no longer be used
                    commit_reg_load(insn, my_dsts, my_ptr_regs,leak_regs)
                    va += insn.size
                    continue
            if state >= 1:
                for reg in [x for x in my_ptr_regs]:
                    if insn_propagates_reg(insn, reg) :
                        dst = insn.operands[0]
                        if dst.type == x86.X86_OP_REG:
                            if dst.reg not in my_ptr_regs:
                                my_ptr_regs.append(dst.reg)
                if is_load_to_reg(insn, my_dsts, my_srcs):
                    state = max(state,2)
                    #  print_ins(va, insn, '+'*(state))
                    commit_load_to_reg(insn, my_dsts, my_srcs,
                                       my_ptr_regs, leak_regs)
                    va += insn.size
                    continue

            reg_overriden = insn_overrides_srcs(insn, my_ptr_regs)
            if reg_overriden:
                my_ptr_regs.remove(reg_overriden)
            if state < 2:
                # ptr loading from ptr sources
                dst,src,imm_scale_wtf = insn_ops(insn)
                reg_overriden = insn_overrides_srcs(insn, [x[0] for x in my_srcs])
                if reg_overriden:
                    if insn.mnemonic in ["pop", "not"]:
                        my_srcs = [x for x in my_srcs if x[0] != dst.reg]
                    # Reg in my_srcs found overridden. what do we do?
                    if not src and insn.mnemonic not in ["pop", "push","not"]:
                        # TODO: remove reg that got popped onto
                        print_ins(va, insn, "no src wtf")
                    if (src and src.type == x86.X86_OP_IMM and insn.id in [x86.X86_INS_XOR]+ARITH_SUB+ARITH_ADD):
                        for (i, (reg, (disp_min, disp_max))) in enumerate(my_srcs):
                            if (reg != reg_overriden):
                                continue
                            if insn.id in ARITH_ADD:
                                my_srcs[i] = (reg, (disp_min - src.imm, disp_max - src.imm))
                            elif insn.id in ARITH_SUB:
                                my_srcs[i] = (reg, (disp_min + src.imm, disp_max + src.imm))
                            elif insn.id == x86.X86_INS_XOR:
                                # this op does not make sense.. it will not be
                                # correctly.
                                print_ins(va, insn, "[DEBUG] problematic xor?")
                                my_srcs[i] = (reg, (disp_min ^ src.imm, disp_max ^ src.imm))
                            else:
                                print("IMPOSSIBLE STATE")
                                exit(23)
                    elif src:
                        #  print_ins(va, insn, "kills src")
                        # only drop if the insn has a src, so dont drop if we
                        # have for example inc
                        my_srcs = [x for x in my_srcs if x[0] != reg_overriden]
            if insn_propagates_src(insn, my_srcs, my_dsts):
                commit_propagate_src(insn, my_srcs)
                #  print_ins(va, insn, "nouse")
            va += insn.size

KERN_PATH = sys.argv[1]
CODE = bytearray()
DATA = bytearray()

START_VA = None

if len(sys.argv) > 2:
    START_VA = int(sys.argv[2], 16)

with open(KERN_PATH, 'rb') as text:
    elffile = ELFFile(text)
    execSections = [s for s in elffile.iter_sections()
                    if s.header.sh_flags & SH_FLAGS.SHF_EXECINSTR]
    for s in execSections:
        h = s.header
        #  print("===> %s f_off=%x\tsz=%x\tva=%x" % (s.name.ljust(14), h.sh_offset, h.sh_size, h.sh_addr))
        file_offset = h.sh_offset
        if START_VA:
            if START_VA < h.sh_addr:
                continue
            if START_VA > h.sh_addr + h.sh_size:
                continue
            file_offset += START_VA - h.sh_addr

        for start in range(file_offset, file_offset + h.sh_size, TARGET_CHUNK_SIZE):
            text.seek(start)
            CODE = bytearray(text.read(min(CODE_CHUNK_SIZE, h.sh_size)))
            code_search(CODE, start + h.sh_addr - h.sh_offset)

sys.exit(1)
