# ~~~
# * Try to find PF_RING include dirs and libraries
#
# Usage of this module as follows:
#
# find_package(PF_RING)
#
# Variables defined by this module:
#
# PF_RING_FOUND                System has PF_RING include and library dirs found
# PF_RING_INCLUDE_DIRS         The PF_RING include directories.
# PF_RING_LIBRARIES            The PF_RING library
# ~~~

# Look for static library
find_library(PF_RING_LIBRARIES libpfring.a PATH_SUFFIXES userland/lib)

find_path(PF_RING_USER_INCLUDE_DIR pfring.h PATH_SUFFIXES userland/lib)

find_path(PF_RING_KERNEL_INCLUDE_DIR linux/pf_ring.h PATH_SUFFIXES kernel)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  PF_RING
  REQUIRED_VARS PF_RING_LIBRARIES PF_RING_KERNEL_INCLUDE_DIR PF_RING_USER_INCLUDE_DIR
  FAIL_MESSAGE "PF_RING not found! Please specify PF_RING_ROOT."
)

set(PF_RING_LIBRARIES ${PF_RING_LIBRARIES} ${CMAKE_DL_LIBS})

mark_as_advanced(PF_RING_KERNEL_INCLUDE_DIR PF_RING_USER_INCLUDE_DIR)

set(PF_RING_INCLUDE_DIRS ${PF_RING_KERNEL_INCLUDE_DIR} ${PF_RING_USER_INCLUDE_DIR})

if(PF_RING_FOUND AND NOT TARGET PF_RING::PF_RING)
  add_library(PF_RING::PF_RING INTERFACE IMPORTED)
  set_property(TARGET PF_RING::PF_RING PROPERTY INTERFACE_LINK_LIBRARIES "${PF_RING_LIBRARIES}")
  set_property(TARGET PF_RING::PF_RING PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${PF_RING_INCLUDE_DIRS}")
endif()
