set(LIBRARY_NAME "riot_tee_attest")

add_library(${LIBRARY_NAME}
    STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/tee_attest.c
    ${RIOT_NANOCBOR}/src/encoder.c
)

target_include_directories(${LIBRARY_NAME}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${RIOT_NANOCBOR}/include
    ${TARGET_DIR}
    ${PROJECT_SOURCE_DIR}/api
    ${PROJECT_SOURCE_DIR}/src/crypto
    ${PROJECT_SOURCE_DIR}/src/rot
    ${PROJECT_SOURCE_DIR}/src/entry
    ${CMSISPATH}/Core/Include
    ${CMSISDEVPATH}
    ${NRFXPATH}/mdk
    ${CRYPTOSERVICE_PATH}/api
    ${CRYPTOSERVICE_PATH}/libs/RIOT/sys/include
)

# nanocbor reaches for <endian.h>; point it at our freestanding byte-order shim
target_compile_definitions(${LIBRARY_NAME}
    PRIVATE
    NANOCBOR_BYTEORDER_HEADER="nanocbor_byteorder.h"
)

target_compile_options(${LIBRARY_NAME}
    PUBLIC
    ${FLAGS}
    "-Wall"
    "-Werror"
)
