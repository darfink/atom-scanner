#pragma once

namespace atom {
  /* Calculates the size of a module
   *
   * @baseAddress The base address of the module
   * @return The size of the module in bytes
   */
  size_t CalculateModuleSize(const void* baseAddress);
}
