cmake_minimum_required(VERSION 2.8)

project(socks)

find_package(Boost REQUIRED COMPONENTS system thread regex)
IF(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  link_directories(${Boost_LIBRARY_DIRS})
ENDIF(Boost_FOUND)

# add_executable(sclient client.cpp)
# target_link_libraries(sclient ${Boost_LIBRARIES})

add_executable(tests tests.cpp client.cpp thirdparty/catch2-main.cpp)
target_link_libraries(tests ${Boost_LIBRARIES})
