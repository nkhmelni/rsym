cmake_minimum_required(VERSION 3.15)
project(rsym LANGUAGES C)

set(CMAKE_C_STANDARD 11)

add_library(rsym_lib STATIC rsym.c)
set_target_properties(rsym_lib PROPERTIES OUTPUT_NAME rsym)

add_executable(rsym main.c)
target_link_libraries(rsym PRIVATE rsym_lib)

