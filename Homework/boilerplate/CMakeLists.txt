cmake_minimum_required(VERSION 2.8)

aux_source_directory(. DIR_SRCS)
add_executable(boilerplate ${DIR_SRCS})
target_include_directories(boilerplate PRIVATE ../HAL/include)
target_link_libraries(boilerplate router_hal readline ncurses)
message(${DIR_SRCS})
message(2333)
