cmake_minimum_required(VERSION 3.22.2)

project(lVPN VERSION 0.2.0)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/)
set(CXX_FLAGS
 -g
 -DCHECK_PTHREAD_RETURN_VALUE
 -D_FILE_OFFSET_BITS=64
 -Wall
 -Wextra
 -Werror
 -Wconversion
 -Wno-unused-parameter
 -Wold-style-cast
 -Woverloaded-virtual
 -Wpointer-arith
 -Wshadow
 -Wwrite-strings
 -march=native
 -std=c++17
 -rdynamic
 )

find_package(OpenSSL REQUIRED)
set(DEP_LIBS
    OpenSSL::Crypto OpenSSL::SSL
)
find_package(Boost REQUIRED COMPONENTS)
if(NOT Boost_FOUND)
    message("Not found Boost")
endif()
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${PROJECT_SOURCE_DIR}/include)

# aux_source_directory(${PROJECT_SOURCE_DIR}/src src_dirs)
set(server_SRCS
    ${PROJECT_SOURCE_DIR}/src/config.cc
    ${PROJECT_SOURCE_DIR}/src/CountDownLatch.cc
    ${PROJECT_SOURCE_DIR}/src/Epoll.cc
    ${PROJECT_SOURCE_DIR}/src/lVPN.cc
    ${PROJECT_SOURCE_DIR}/src/logging.cc
    ${PROJECT_SOURCE_DIR}/src/utils.cc
)
add_executable(lVPNsrv Server.cc ${server_SRCS})
target_link_libraries(lVPNsrv ${DEP_LIBS})
target_link_libraries(lVPNsrv crypt)

set(client_SRCS
    ${PROJECT_SOURCE_DIR}/src/config.cc
    ${PROJECT_SOURCE_DIR}/src/CountDownLatch.cc
    ${PROJECT_SOURCE_DIR}/src/lVPNclient.cc
    ${PROJECT_SOURCE_DIR}/src/logging.cc
)
link_directories(${PROJECT_SOURCE_DIR}/lib)
add_executable(lVPNclient Client.cc ${client_SRCS})
target_link_libraries(lVPNclient -static ssl crypto)