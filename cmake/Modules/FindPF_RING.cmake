# - Try to find PF_RING include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(PF_RING)
#
# Variables defined by this module:
#
#  PF_RING_FOUND                System has PF_RING include and library dirs found
#  PF_RING_INCLUDE_DIRS         The PF_RING include directories.
#  PF_RING_LIBRARIES            The PF_RING library

find_library(PF_RING_LIBRARIES 
	pfring 
	${PF_RING_HOME}
	${PF_RING_HOME}/userland/
	${PF_RING_HOME}/userland/lib
)

find_path(PF_RING_USER_INCLUDE_DIR pfring.h
	HINTS 
	${PF_RING_HOME}
	${PF_RING_HOME}/userland
	${PF_RING_HOME}/userland/lib
)

if(PF_RING_USER_INCLUDE_DIR)
	set(PF_RING_INCLUDE_DIRS ${PF_RING_INCLUDE_DIRS}
		${PF_RING_USER_INCLUDE_DIR}
	)
endif()

find_path(PF_RING_KERNEL_INCLUDE_DIR linux/pf_ring.h
	HINTS 
	${PF_RING_HOME}
	${PF_RING_HOME}/kernel
)

if(PF_RING_KERNEL_INCLUDE_DIR)
	set(PF_RING_INCLUDE_DIRS ${PF_RING_INCLUDE_DIRS}
		${PF_RING_KERNEL_INCLUDE_DIR}
	)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PF_RING
    REQUIRED_VARS 
		PF_RING_LIBRARIES 
		PF_RING_KERNEL_INCLUDE_DIR 
		PF_RING_USER_INCLUDE_DIR
    FAIL_MESSAGE 
		"PF_RING not found! Please specify PF_RING_HOME."
)

mark_as_advanced(
	PF_RING_KERNEL_INCLUDE_DIR
	PF_RING_USER_INCLUDE_DIR
)

set(PF_RING_INCLUDE_DIRS ${PF_RING_KERNEL_INCLUDE_DIR} ${PF_RING_USER_INCLUDE_DIR})
