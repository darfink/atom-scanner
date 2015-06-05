#include <atom-scanner/SignatureScanner.hpp>
#include <atom-ex/WindowsException.hpp>
#include <psapi.h>
#include <cassert>

namespace atom {
  SignatureScanner::SignatureScanner(void* address) :
      mBaseAddress(0),
      mModuleSize(0) {
    assert(address != nullptr);

    HMODULE module;
    ATOM_WINDOWS_ASSERT(GetModuleHandleExW(
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, static_cast<wchar_t*>(address), &module));

    mModuleHandle.reset(module, [](void* handle) {
      if(handle != nullptr) {
        assert(FreeLibrary(static_cast<HMODULE>(handle)));
      }
    });

    MODULEINFO moduleInfo;
    ATOM_WINDOWS_ASSERT(GetModuleInformation(
      GetCurrentProcess(), module, &moduleInfo, sizeof(MODULEINFO)));

    mBaseAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
    mModuleSize = moduleInfo.SizeOfImage;
  }

  void* SignatureScanner::FindSymbol(const std::string& symbol) const {
    return GetProcAddress(static_cast<HMODULE>(mModuleHandle.get()), symbol.c_str());
  }
}
