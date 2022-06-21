int main(int argc, char *argv[])
{
    asm volatile("mov 0x20(%r13), %r14"); //<- useless source
    asm volatile("mov 0x20(%r13), %r12");
    asm volatile("mov 0x28(%r13), %r15");
    asm volatile("movzx (%r14), %eax");
    asm volatile("mov %rax, (%rax, %r12)");
    return 0;
}
