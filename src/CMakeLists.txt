cmake_minimum_required(VERSION 3.1..3.11)

if(${CMAKE_VERSION} VERSION_LESS 3.12)
  cmake_policy(VERSION ${CMAKE_VERSION})
endif()

project(dt)

add_executable(dtclient dtclient.cpp)
target_link_libraries(dtclient PUBLIC Boost::system Boost::thread PRIVATE gsl)
target_compile_features(dtclient PRIVATE cxx_std_14)
target_include_directories(dtclient PRIVATE ../include)
set_target_properties(dtclient PROPERTIES CXX_EXTENSIONS off)

add_executable(dtserver dtserver.cpp)
target_link_libraries(dtserver PUBLIC Boost::system Boost::thread)
target_compile_features(dtserver PRIVATE cxx_std_14)
target_include_directories(dtserver PRIVATE ../include)
set_target_properties(dtserver PROPERTIES CXX_EXTENSIONS off)
