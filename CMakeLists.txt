cmake_minimum_required(VERSION 3.25)
project(drfin LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(DRFIN_BUILD_EXAMPLES ON)

find_package(Drogon CONFIG REQUIRED)

add_library(misfin src/client.cpp src/gemmail.cpp src/server.cpp src/url.cpp src/utils.cpp)
target_include_directories(misfin PUBLIC include)
target_link_libraries(misfin PUBLIC Drogon::Drogon)
target_compile_options(misfin PRIVATE -Wall -Wextra -Wpedantic -Werror)

include(CTest)
if(BUILD_TESTING)
    add_executable(gemmail-test tests/gemmail_test.cpp)
    target_link_libraries(gemmail-test PRIVATE misfin)
    add_test(NAME gemmail COMMAND gemmail-test)
endif()

if(DRFIN_BUILD_EXAMPLES)
    add_executable(misfin-send examples/send.cpp)
    target_link_libraries(misfin-send PRIVATE misfin)

    add_executable(misfin-receive examples/receive.cpp)
    target_link_libraries(misfin-receive PRIVATE misfin)
endif()
