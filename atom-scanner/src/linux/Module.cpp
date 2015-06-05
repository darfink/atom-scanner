#include <atom-ex/SystemException.hpp>

namespace atom {
  size_t CalculateModuleSize(const void* baseAddress) {
    assert(baseAddress != nullptr);

    std::ifstream fstream("/proc/self/maps");
    std::string input;

    ATOM_SYSTEM_ASSERT(fstream.good());

    bool found = false;
    uintptr_t address = reinterpret_cast<uintptr_t>(baseAddress);
    uintptr_t lower, upper, offset;
    char permissions[4];
    byte major, minor;
    uint inode;

    uintptr_t moduleBase, moduleEnd;
    uint moduleNode;

    while(std::getline(fstream, input)) {
      if(sscanf(input.c_str(), "%lx-%lx %s %lx %hhu:%hhu %du",
        &lower, &upper, permissions, &offset, &major, &minor, &inode) != 7) {
        continue;
      }

      if(address == lower && !found) {
        moduleBase = lower;
        moduleNode = inode;
        moduleEnd = upper;

        found = true;
        continue;
      } else if(found) {
        if(inode != moduleNode) {
          break;
        }

        // Update the upper bound
        moduleEnd = upper;
      }
    }

    if(!found) {
      throw Exception(ATOM_EXCEPTION_INFO, "Couldn't find memory module");
    }

    // Calculate the final module size
    return (moduleEnd - moduleBase);
  }
}
