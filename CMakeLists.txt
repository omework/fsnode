cmake_minimum_required(VERSION 3.28)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(fsnode C)

set(CMAKE_C_STANDARD 23)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include OpenSSL headers
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories("include")
include_directories("/opt/homebrew/Cellar/libmagic/5.45/include")
include_directories("/opt/homebrew/Cellar/jansson/2.14/include")
include_directories("/opt/homebrew/Cellar/libuv/1.48.0/include")
include_directories("/opt/homebrew/Cellar/duckdb/1.0.0/include")
include_directories("/opt/homebrew/Cellar/zlog/1.2.18/include")

add_executable(fsnode
        main.c
        include/fsnode.h
        include/env.h
        include/map.h
        include/list.h
        include/crypto.h
        include/utils.h
        include/http.h
        include/conn.h
        include/aws.h
        include/server.h
        include/echo.h
        include/cdn.h
        src/map.c
        src/env.c
        src/utils.c
        src/crypto.c
        src/crypto.c
        src/list.c
        src/http.c
        src/http.c
        src/conn.c
        src/aws.c
        src/server.c
        src/fsnode.c
        src/echo.c
        src/cdn.c
)

find_library(LIBMAGIC NAMES magic)
find_library(LIBMHD NAMES microhttpd)
find_library(LIBJANSSON NAMES jansson)
find_library(LIBUV NAMES uv)
find_library(LIBDUCKDB NAMES duckdb)
find_library(LIBZLOG NAMES zlog)

target_link_libraries(fsnode
        ${LIBMHD}
        ${LIBMAGIC}
        ${LIBJANSSON}
        ${LIBUV}
        ${LIBDUCKDB}
        ${LIBZLOG}
        OpenSSL::SSL OpenSSL::Crypto)
