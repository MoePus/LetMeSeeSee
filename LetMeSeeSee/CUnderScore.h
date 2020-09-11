#pragma once
extern "C" size_t __ImageBase;
extern "C" {
    int mainCRTStartup();
    const size_t GetCurrentModule();
    // #pragma comment( linker, "/entry:\"mainSelector\"" )
}