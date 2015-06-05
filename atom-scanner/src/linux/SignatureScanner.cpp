#include <atom-scanner/SignatureScanner.hpp>
#include <fstream>
#include <cstdio>
#include <sys/mman.h>
#include <dlfcn.h>

#include "Module.hpp"

namespace atom {
  SignatureScanner::SignatureScanner(void* address) :
      mBaseAddress(0),
      mModuleSize(0) {
    assert(address != nullptr);

    Dl_info info;
    if(!dladdr(address, &info)) {
      throw Exception(ATOM_EXCEPTION_INFO, dlerror());
    }

    mModuleHandle.reset(dlopen(info.dli_fname, RTLD_NOW), +[](void* handle) {
      if(handle != nullptr) {
        assert(dlclose(handle) == 0);
      }
    });

    if(!mModuleHandle) {
      throw Exception(ATOM_EXCEPTION_INFO, dlerror());
    }

    mBaseAddress = reinterpret_cast<uintptr_t>(info.dli_fbase);
    mModuleSize = CalculateModuleSize(info.dli_fbase);
  }

  void* SignatureScanner::FindSymbol(const std::string& symbol) const {
    return dlsym(mModuleHandle.get(), symbol.c_str());
  }
}
