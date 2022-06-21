// leak secret before dereferencing rb
int main(int argc, char *argv[])
{
    asm volatile("mov 0x20(%r13), %r14");
    asm volatile("movzx (%r14), %eax");
    asm volatile("mov 0x28(%r13), %r15");
    asm volatile("add %rax, %r14");
    asm volatile("mov %rax, (%rax)");
    return 0;
}
