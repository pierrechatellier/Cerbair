cmake_minimum_required(VERSION 3.20)
project(infodrone_parser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_library(infodrone_core STATIC
  src/pcapng/PcapNgReader.cpp
  src/wlan/WlanFrame.cpp
  src/infodrone/InfoDroneDecoder.cpp
)
target_include_directories(infodrone_core PUBLIC src)
if(MSVC)
  # Use MSVC warning level 4 instead of GCC/Clang -W flags
  target_compile_options(infodrone_core PRIVATE /W4)
else()
  target_compile_options(infodrone_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(infodroneParser src/main.cpp)
target_link_libraries(infodroneParser PRIVATE infodrone_core)

option(BUILD_TESTING "Build unit tests" ON)
if(BUILD_TESTING)
  enable_testing()
  include(FetchContent)
  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.5.2
  )
  FetchContent_MakeAvailable(Catch2)

  add_executable(infodrone_tests
    tests/test_byte_reader.cpp
    tests/test_beacon.cpp
    tests/test_infodrone.cpp
    tests/test_pcapng_reader.cpp
  )
  target_link_libraries(infodrone_tests
    PRIVATE infodrone_core Catch2::Catch2WithMain)

  include(CTest)
  include(Catch)
  catch_discover_tests(infodrone_tests)
endif()
