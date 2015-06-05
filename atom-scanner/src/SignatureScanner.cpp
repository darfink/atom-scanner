#include <atom-scanner/SignatureScanner.hpp>
#include <atom-memory/MemoryRegion.hpp>
#include <algorithm>
#include <cassert>
#include <cstring>

namespace atom {
  // Prevent tons of typing
  typedef unsigned char byte;

  void* SignatureScanner::FindSignature(
      const std::vector<byte>& signature,
      const char* mask,
      size_t offset,
      size_t length) const {
    assert(mask != nullptr);
    assert(signature.size() == std::strlen(mask));

    uintptr_t start = mBaseAddress + offset;
    uintptr_t end = mBaseAddress + std::min(mModuleSize, length);

    assert(start < end);
    size_t x = 0;

    while(start < end) {
      // When a memory region is instantiated with a 'size' argument, it will
      // retrieve all pages located at the supplied address, which lie
      // consecutively with the same flags (i.e the first memory page have the
      // exact same attributes as the last page in the region). So if one page
      // within the region is readable, the whole region is readable.
      MemoryRegion region(reinterpret_cast<void*>(start));

      auto page = region.begin();

      // Calculate the bounds for the current memory region
      size_t regionSize = reinterpret_cast<uintptr_t>(page->base) + region.GetRegionSize();

      // Check whether the current region is readable or not
      if(!(page->currentFlags & Memory::Read) || !page->committed || page->guarded) {
        start = regionSize;
        x = 0;

        continue;
      }

      for(bool quit = false; start < regionSize && !quit; start++) {
        for(; x < signature.size(); x++) {
          // Ensure that we aren't intruding in a new memory region
          if((start + x) >= regionSize) {
            // We must decrement 'x', otherwise it might equal
            // 'signature.size()' and we 'think' we have a match
            quit = true;
            x--;

            break;
          }

          // Exit the loop if the signature did not match with the source
          if(mask[x] != '?' && signature[x] != reinterpret_cast<byte*>(start)[x]) {
            break;
          }
        }

        // If the increment count equals the signature length,
        // we know we have a match!
        if(x == signature.size()) {
          return reinterpret_cast<void*>(start);
        } else {
          x = 0;
        }
      }
    }

    return nullptr;
  }
}
