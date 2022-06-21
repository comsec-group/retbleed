int main(int argc, char *argv[])
{
    asm volatile("mov %r13, %r11");
    asm volatile("mov 0x20(%r11), %r14");
    asm volatile("mov 0x28(%r11), %r15");
    asm volatile("mov (%r15), %ax");
    asm volatile("mov (%r14, %rax), %rax");
    return 0;
}
