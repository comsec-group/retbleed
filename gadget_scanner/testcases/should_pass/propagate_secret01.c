// SPDX-License-Identifier: GPL-3.0-only
int main(int argc, char *argv[])
{
    asm volatile("mov 0x20(%r13), %r14");
    asm volatile("mov 0x28(%r13), %r15");
    asm volatile("mov %rdx, %r13");
    asm volatile("mov (%r15), %ax");
    asm volatile("mov %rax, %rbx");
    asm volatile("mov (%r14, %rbx), %rax");
    return 0;
}
