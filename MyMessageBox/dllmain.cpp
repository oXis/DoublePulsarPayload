#include <Windows.h>

extern "C" VOID __declspec(dllexport) TestFunction0();
extern "C" VOID __declspec(dllexport) TestFunction1();
extern "C" VOID __declspec(dllexport) TestFunction2();
extern "C" VOID __declspec(dllexport) TestFunction3();
extern "C" VOID __declspec(dllexport) TestFunction4();
extern "C" VOID __declspec(dllexport) TestFunction5();
extern "C" VOID __declspec(dllexport) TestFunction6();
extern "C" VOID __declspec(dllexport) TestFunction7();
extern "C" VOID __declspec(dllexport) TestFunction8();
extern "C" VOID __declspec(dllexport) TestFunction9();

extern "C" VOID __declspec(dllexport) TestFunction0()
{
    MessageBoxA(NULL, "Hello from test function 0", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction1()
{
    MessageBoxA(NULL, "Hello from test function 1", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction2()
{
    MessageBoxA(NULL, "Hello from test function 2", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction3()
{
    MessageBoxA(NULL, "Hello from test function 3", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction4()
{
    MessageBoxA(NULL, "Hello from test function 4", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction5()
{
    MessageBoxA(NULL, "Hello from test function 5", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction6()
{
    MessageBoxA(NULL, "Hello from test function 6", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction7()
{
    MessageBoxA(NULL, "Hello from test function 7", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction8()
{
    MessageBoxA(NULL, "Hello from test function 8", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction9()
{
    MessageBoxA(NULL, "Hello from test function 9", "Hello", MB_OK);
}


BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID)
{

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        MessageBoxA(NULL, "DLL_PROCESS_ATTACH", "Hello", MB_OK);
    }
    break;
    case DLL_PROCESS_DETACH:
    {
        MessageBoxA(NULL, "DLL_PROCESS_DETACH", "Hello", MB_OK);
    }
    break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}