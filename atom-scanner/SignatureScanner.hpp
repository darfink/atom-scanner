#pragma once

#include <atom-ex/Exception.hpp>
#include <memory>
#include <vector>

namespace atom {
  /* Signature scanner
  *
  * The signature scanner implements a cross-platform way of searching for
  * binary patterns within a module in the current process. This is performed
  * by starting from a base address and continuing comparing bytes to a
  * signature, ignoring specific indexes specified by the accompanied mask.
  *
  */
  class SignatureScanner {
  private:
    // Private members
    std::shared_ptr<void> mModuleHandle;
    uintptr_t mBaseAddress;
    size_t mModuleSize;

  public:
    /* Signature scanner exception */
    ATOM_DEFINE_EXCEPTION(Exception);

    /* Construct a signature scanner
    *
    * Creates a signature scanner from an address located within a module.
    * The address is resolved into the module that contains it. If the address
    * cannot be resolved, an <Exception> will be thrown. All memory regions
    * that are readable within the module is indexed.
    *
    * @address An address that resides within a module
    */
    explicit SignatureScanner(void* address);

    /* Search for a signature
    *
    * Tries to find a signature within the constructed memory region. If an OS
    * call fails during the scan an <Exception> will be thrown. Any memory page
    * and/or region that is read-protected will skipped in the search. This
    * includes regions that are page guarded on Windows.
    *
    * The search is done by using simple pointer arithmetics. The comparison is
    * done by using direct memory access of the processed region and the
    * supplied byte signature.
    *
    * NOTE: The method does not throw an <Exception> when no result is found.
    *
    * @signature The description of the signature pattern in hex values.
    *            Values that are to be ignored by the mask can be any value.
    *
    * @mask The mask consists of a character array that must have an equal
    *       length compared to the the signature. Each index corresponds to the
    *       respective index of the signature. A question mark character
    *       indicates that the byte should be ignored. Any other mask value
    *       includes the byte in the pattern search. The mask must be
    *       null-terminated.
    *
    * @offset The start offset for the search. The value is relative to the
    *         modules base address. An offset of zero will search from start.
    *
    * @length The maximum distance the search will be performed (counted in
    *         bytes). The length will be capped to the module size.
    *
    * @return The memory address of the first match of the signature,
    *         otherwise zero is returned (i.e null).
    */
    void* FindSignature(
      const std::vector<unsigned char>& signature,
      const char* mask,
      size_t offset = 0,
      size_t length = npos) const;

    /* Search for a module symbol
    *
    * Uses the native OS method (e.g 'dlsym', 'GetProcAddress') for retrieving
    * a symbol within the module.  * This method is merely exposed as a
    * convenience for the user.
    *
    * @symbol The unique symbol to resolve within the module
    *
    * @return The symbol address, otherwise zero is returned (i.e null).
    */
    void* FindSymbol(const std::string& symbol) const;

    /* Get the base address of the module
    *
    * @return The base address of the module.
    */
    void* GetBaseAddress() const;

    /* Get the size of the module
    *
    * @return The size of the module in bytes.
    */
    size_t GetModuleSize() const;

  public:
    /* Maximum value for size_t
    *
    * This exists to mimic the functionality of 'std::string::substr' in the
    * standard string class, but for memory regions instead.
    */
    static const size_t npos = -1;
  };

  inline void* SignatureScanner::GetBaseAddress() const {
    return reinterpret_cast<void*>(mBaseAddress);
  }

  inline size_t SignatureScanner::GetModuleSize() const {
    return mModuleSize;
  }
}
