cmake_minimum_required(VERSION 3.1..3.11)

if(${CMAKE_VERSION} VERSION_LESS 3.12)
  cmake_policy(VERSION ${CMAKE_VERSION})
endif()

add_executable(s4server s4server.cpp)
target_link_libraries(s4server PUBLIC Boost::system Boost::thread)
target_compile_features(s4server PRIVATE cxx_std_14)
target_include_directories(s4server PRIVATE ../include)
set_target_properties(s4server PROPERTIES CXX_EXTENSIONS off)

add_executable(s5server s5main.cpp s5server.cpp s5session.cpp)
target_link_libraries(s5server PUBLIC Boost::system Boost::thread Boost::log)
target_compile_features(s5server PRIVATE cxx_std_14)
target_include_directories(s5server PRIVATE ../include)
set_target_properties(s5server PROPERTIES CXX_EXTENSIONS off)
