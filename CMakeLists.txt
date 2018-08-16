cmake_minimum_required(VERSION 3.1..3.11)

if(${CMAKE_VERSION} VERSION_LESS 3.12)
  cmake_policy(VERSION ${CMAKE_VERSION})
endif()

project(socks)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# target cpu
if("${TARGET_CPU}" STREQUAL "amd64")
    set(CMAKE_SIZEOF_VOID_P 8)
    set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS TRUE)
    set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS FALSE)
elseif("${TARGET_CPU}" STREQUAL "x86")
    set(CMAKE_SIZEOF_VOID_P 4)
    set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS FALSE)
    set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS TRUE)

    if (GCC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
        set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -m32")
    endif()
else()
    message(FATAL_ERROR "Unsupported CPU: ${TARGET_CPU}")
endif()

option(USE_CCACHE "Use ccache if available" ON)
if(USE_CCACHE)
  find_program(CCACHE_PROGRAM ccache)
  if(CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
  endif()
endif()

# use clang-tidy if available
option(USE_CLANG_TIDY "Use clang-tidy to perform code analysis" ON)
if(USE_CLANG_TIDY)
  if(CMAKE_VERSION VERSION_GREATER 3.6)
    option(CLANG_TIDY_FIX "Perform fixes for Clang-Tidy" OFF)
    find_program(
      CLANG_TIDY_PATH
      NAMES clang-tidy
      )

    if(CLANG_TIDY_PATH)
      if(CLANG_TIDY_FIX)
	set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_PATH}" "-fix")
      else()
	set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_PATH}")
      endif()
    endif()
  endif()
endif()

# use iwyu if available
option(USE_IWYU "Use include-what-you-use to perform include dependencies check" OFF)
if(USE_IWYU)
  if(CMAKE_VERSION VERSION_GREATER 3.3)
    find_program(
      IWYU_PATH
      NAMES include-what-you-use iwyu
      )

    if(IWYU_PATH)
      set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "${IWYU_PATH}")
    endif()
  endif()
endif()

# boost
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

if(MSVC)
  find_package(Boost 1.60 REQUIRED COMPONENTS system thread log)
else()
  find_package(Boost 1.54 REQUIRED COMPONENTS system thread log)
endif()
message(STATUS "Boost version: ${Boost_VERSION}")

# gsl-lite
set(GSL_LITE_INCLUDE_DIR thirdparty)
add_library(gsl INTERFACE)
target_include_directories(gsl INTERFACE ${GSL_LITE_INCLUDE_DIR})

add_subdirectory(src)
add_subdirectory(test)
