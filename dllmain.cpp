#include <iostream>
#include <Windows.h>



/// <summary>
/// overwrites the bytes of the pointer with our own jump instruction which will jump to the pointer we want to.
/// </summary>
/// <param name="offset to jump from"></param>
/// <param name="offset to jump to"></param>
void jump(uintptr_t jumpfrom, uintptr_t jumpto)
{
    //for virtual protect
    DWORD old;

    //this gets written to the part we want to jump from
    BYTE jmp_asm[] = {
0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp to qword
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // padding for pointer which we are going to write on
    };

    //writes the address we want to jump to in the shellcode
    memcpy(jmp_asm + 6, &jumpto, 8);

    //change access of the pointer we need to overwrite so we can do write to it
    if (!VirtualProtect((void*)jumpfrom, 14, PAGE_EXECUTE_READWRITE, &old))
    {
        MessageBoxA(0, "Failed To Change Access Protection For Pointer!", "PoC By furiosdestruct#9701", MB_OK | MB_ICONERROR);
        exit(1);
    }

    //write the shellcode to the pointer
    memcpy((void*)jumpfrom, jmp_asm, 14);
}

void init()
{
    //get baseaddress of current process or the process which we are trying to bypass,
    //in my case this is a dll which is going to be injected in the target process.
    uintptr_t baseaddress = (uintptr_t)GetModuleHandleA(0);

    //the offset for the pointer we are going to jump from in my case the login
    uintptr_t jumpfrom = 0x7F406;

    //the offset for the pointer which we are going to jump onto in my case the menu
    uintptr_t jumpto = 0x7F5A6;

    std::cout << "\nArgument 1 (jump from): 0x" << std::hex << baseaddress + jumpfrom << std::endl;
    std::cout << "Argument 2 (jump to): 0x" << std::hex << baseaddress + jumpto << std::endl;
    //call the function
    jump(baseaddress + jumpfrom, baseaddress + jumpto);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        init();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

