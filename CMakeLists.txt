cmake_minimum_required(VERSION 3.5)

project (adsc-snark)


set(
        CURVE
        "BN254"
        CACHE
        STRING
        "Default curve: one of BN254, BN183, BN124, GMV181, GMV97, GMV58"
)

option(
        DEBUG
        "Enable debugging mode"
        OFF
)
option(
        LOWMEM
        "Limit the size of multi-exponentiation tables, for low-memory platforms"
        OFF
)
option(
        MULTICORE
        "Enable parallelized execution, using OpenMP"
        OFF
)
option(
        BINARY_OUTPUT
        "In serialization, output raw binary data (instead of decimal), which is smaller and faster."
        ON
)
option(
        MONTGOMERY_OUTPUT
        "Serialize Fp elements as their Montgomery representations (faster but not human-readable)"
        OFF
)
option(
        USE_PT_COMPRESSION
        "Use point compression"
        ON
)
option(
        PROFILE_OP_COUNTS
        "Collect counts for field and curve operations"
        OFF
)
option(
        USE_MIXED_ADDITION
        "Convert each element of the key pair to affine coordinates"
        OFF
)

option(
        WITH_SUPERCOP
        "Support for Ed25519 signatures required by ADSNARK"
        ON
)

option(
        WITH_PROCPS
        "Use procps for memory profiling"
        OFF
)

option(
        CPPDEBUG
        "Enable debugging of C++ STL (does not imply DEBUG)"
        OFF
)

option(
        PERFORMANCE
        "Enable link-time and aggressive optimizations"
        OFF
)

option(
        USE_ASM
        "Use architecture-specific optimized assembly code"
        ON
)

option(
        SIGNATURE_SNARKFRIENDLY
        "Use Snark-friendly signature scheme for adsc-snark"
        ON
)

option(ETHSNARKS_DISABLE_TESTS "Disable ethsnarks tests" OFF)
option(ETHSNARKS_DISABLE_UTILS "Disable ethsnarks utilties" ON)
option(ETHSNARKS_DISABLE_PINOCCHIO "Disable pinocchio / xjsnark compatibility" OFF)

option(ETHSNARKS_NO_THREADS "Disable testing for threads support" OFF)

set(
        OPT_FLAGS
        ""
        CACHE
        STRING
        "Override C++ compiler optimization flags"
)


set (CMAKE_CXX_STANDARD 14) # The latest googletest commit requires c++14, for libsnark alone, this is not needed

if("${DEPENDS_DIR}" STREQUAL "")
  set(
          DEPENDS_DIR
          "${CMAKE_CURRENT_SOURCE_DIR}/depends"
          CACHE
          STRING
          "Optionally specify the dependency installation directory relative to the source directory (default: inside dependency folder)"
  )
else()
  set(DEPENDS_DIR "${DEPENDS_DIR}")
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  # Common compilation flags and warning configuration
  set(
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS}  -Wall -Wextra -Wfatal-errors" # Removed -std=c++11
  )
  if("${MULTICORE}")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
  endif()
  # Default optimizations flags (to override, use -DOPT_FLAGS=...)
  if("${OPT_FLAGS}" STREQUAL "")
    if("${DEBUG}")
      set(
              OPT_FLAGS
              "-ggdb3 -O0"
      )
    else()
      set(
              OPT_FLAGS
              "-O2 -march=native -mtune=native"
      )
    endif()
  endif()
endif()

set(
  CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} ${OPT_FLAGS}"
)


# GMP
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)

include(FindPkgConfig)
pkg_check_modules(
        CRYPTO
        REQUIRED

        libcrypto
)

if("${WITH_PROCPS}")
  pkg_check_modules(
          PROCPS
          REQUIRED

          libprocps
  )
else()
  add_definitions(
          -DNO_PROCPS
  )
endif()

# Enable Boost for program_options
FIND_PACKAGE( Boost 1.40 COMPONENTS program_options REQUIRED )
INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} )

add_definitions(
        -DCURVE_${CURVE}
)

enable_testing()

if(${CURVE} STREQUAL "BN128")
  add_definitions(
          -DBN_SUPPORT_SNARK=1
  )
endif()

if("${DEBUG}")
  add_definitions(-DDEBUG=1)
endif()

if("${LOWMEM}")
  add_definitions(-DLOWMEM=1)
endif()

if("${MULTICORE}")
  add_definitions(-DMULTICORE=1)
endif()

if("${BINARY_OUTPUT}")
  add_definitions(-DBINARY_OUTPUT)
endif()

if("${MONTGOMERY_OUTPUT}")
  add_definitions(-DMONTGOMERY_OUTPUT)
endif()

if(NOT "${USE_PT_COMPRESSION}")
  add_definitions(-DNO_PT_COMPRESSION=1)
endif()

if("${PROFILE_OP_COUNTS}")
  add_definitions(-DPROFILE_OP_COUNTS=1)
endif()

if("${USE_MIXED_ADDITION}")
  add_definitions(-DUSE_MIXED_ADDITION=1)
endif()

if("${CPPDEBUG}")
  add_definitions(-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC)
endif()

if("${PERFORMANCE}")
  add_definitions(-DNDEBUG)
  set(
          CMAKE_CXX_FLAGS
          "${CMAKE_CXX_FLAGS} -flto -fuse-linker-plugin"
  )
  set(
          CMAKE_EXE_LINKER_FLAGS
          "${CMAKE_EXE_LINKER_FLAGS} -flto"
  )
endif()

if("${USE_ASM}")
  add_definitions(-DUSE_ASM)
endif()

if("${SIGNATURE_SNARKFRIENDLY}")
  add_definitions(
          -DSIGNATURE_SNARKFRIENDLY
  )
endif()

if("${USE_LINKED_LIBRARIES}")
  # libfqfft
  find_path(LIBFQFFT_INCLUDE_DIR NAMES libfqfft)
  set(LIBFQFFT_DIRECTORY ${LIBFQFFT_INCLUDE_DIR}/libfqfft)
  include_directories(${LIBFQFFT_DIRECTORY})

  # libff
  find_path(LIBFF_INCLUDE_DIR NAMES libff)
  include_directories(${LIBFF_INCLUDE_DIR}/libff)
  find_library(LIBFF_LIBRARIES NAMES ff libff)
endif()



include_directories(.)
include_directories(depends/)
include_directories(depends/libsnark/)
include_directories(depends/libff)
include_directories(depends/libfqfft)

include_directories(depends/ethsnarks/src)

# Add a `make check` target that builds and tests
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

add_subdirectory(depends)
add_subdirectory(application)
add_subdirectory(adscsnark-strawman)

