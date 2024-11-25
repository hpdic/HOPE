# CMakeLists.txt

# 设置 CMake 最低版本和项目名称
cmake_minimum_required(VERSION 3.10)
project(AES_Paillier_Benchmark)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 指定包含头文件的目录
include_directories(include)

# 查找 Crypto++ 和 Paillier 库
find_library(CRYPTOPP_LIB crypto++ REQUIRED)

# 指定源文件
set(SOURCES
    src/main.cpp
    src/encryption_test.cpp
)

# 添加可执行文件
add_executable(benchmark ${SOURCES})

# 链接库
target_link_libraries(benchmark ${CRYPTOPP_LIB})