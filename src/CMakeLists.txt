
cmake_minimum_required(VERSION 3.13)

project(SQLiPass)

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_library(SQLiPass MODULE
  SQLiPass.cpp
)

set_target_properties(SQLiPass PROPERTIES
  COMPILE_FLAGS "-fno-rtti"
)
