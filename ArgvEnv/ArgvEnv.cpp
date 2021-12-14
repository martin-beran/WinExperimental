#include <iostream>

int main(int argc, char* argv[])
{
    std::cout << "Command line:\n";
    for (int i = 0; i < argc; ++i)
        std::cout << "argv[" << i << "]=" << argv[i] << "\n";
    std::cout << "\nEnvironment:\n";
    for (char** e = _environ; *e; ++e)
        std::cout << *e << "\n";
    return 0;
}                                                                                                                       