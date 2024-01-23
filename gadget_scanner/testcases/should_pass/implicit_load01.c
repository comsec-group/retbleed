// SPDX-License-Identifier: GPL-3.0-only
int main(int argc, char *argv[])
{
    asm volatile("mov 0x20(%r13), %r14");
    asm volatile("mov 0x28(%r13), %r15");
    asm volatile("xor (%r14), %bx");
    asm volatile("mov %rax, (%rbx, %r15)");
    return 0;
}
