cmake_minimum_required(VERSION 3.30)
project(attacker)

set(CMAKE_CXX_STANDARD 20)

add_executable(attacker main.cpp)
target_link_libraries(attacker dwmapi)