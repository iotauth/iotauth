cmake_minimum_required(VERSION 3.5)
project(client)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    CMakeLists.txt
    main.cpp library/Properties.hpp library/Properties.cpp library/Structures.hpp)

add_executable(client ${SOURCE_FILES})