#/usr/bin/cmake

cmake_minimum_required (VERSION 2.8)

MESSAGE("cmake thriftServer project...")

PROJECT(thriftServer)

MESSAGE(PROJECT_BINARY_DIR=${PROJECT_BINARY_DIR})
MESSAGE(PROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR})

#set environment var
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
MESSAGE(EXECUTABLE_OUTPUT_PATH=${EXECUTABLE_OUTPUT_PATH})

#set environment var
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
MESSAGE(LIBRARY_OUTPUT_PATH=${LIBRARY_OUTPUT_PATH})

ADD_DEFINITIONS(
	-O0 -g -W -Wall -std=c++11
	-Wunused-variable -Wunused-parameter -Wunused-function -Wunused
	-Wno-deprecated -Woverloaded-virtual -Wwrite-strings
	-DDEBUG -DLINUX
)

INCLUDE_DIRECTORIES(
  	/usr/local/include/thrift
    /usr/local/include/boost
	.
	./gen-cpp
	/usr/local/include
)

LINK_DIRECTORIES(/usr/local/lib /usr/local/lib64 /usr/lib/)

#add link library
SET(LIBRARIES pthread c m dl
    thrift event thriftnb gocommonlib
)

AUX_SOURCE_DIRECTORY(. SRC_CPP)
AUX_SOURCE_DIRECTORY(./gen-cpp THRIFT_CPP)
MESSAGE(SRC_CPP=${SRC_CPP})
MESSAGE(THRIFT_CPP=${THRIFT_CPP})
SET(TARGET_CPP
	${SRC_CPP}
	${THRIFT_CPP}
)

SET(TARGET_BIN thriftServer)
ADD_EXECUTABLE(${TARGET_BIN} ${TARGET_CPP})
TARGET_LINK_LIBRARIES(${TARGET_BIN} ${LIBRARIES})
