// SPDX-License-Identifier: GPL-3.0-only
int main(int argc, char *argv[])
    // r13 = MemPtr();
{
    // MemPtr = r13, off=0x20 ; MemChunk is at r13+0x20
    //
    // PtrReg = r14, d=0x10, ptr=MemPtr(r13,0x20, mem)
    asm volatile("mov 0x30(%r13), %r14");

    // find MemPtrs with r13, off += 0x100 => MemPtr(r13, 0x120)
    asm volatile("sub $0x100, %r13");

    // find MemPtrs with r13, off += 0x100 => MemPtr(r13, 0x120)
    /* asm volatile("xor $0x100, %r13"); */

    // PtrReg = r15, d=0x08, ptr=MemPtr(r13,0x120)
    asm volatile("mov 0x128(%r13), %r15");

    /* mov 0, r13 => Regs.r13 = dead() */
    //
    // Go to PtrRegs find MemPtrs if uses Regs.r13<MemPtr> (noone does because
    // r13 is dead().
    /* add 0x3, %r13  */


    // LeakRegs(rax, ptr=PtrReg)
    asm volatile("mov (%r15), %ax");

    asm volatile("mov (%r14, %rax), %rax");
    return 0;
}
