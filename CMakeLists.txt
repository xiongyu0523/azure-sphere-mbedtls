#  Copyright (c) Microsoft Corporation. All rights reserved.
#  Licensed under the MIT License.

cmake_minimum_required (VERSION 3.10)

project (azure-sphere-mbedtls C)

azsphere_configure_tools(TOOLS_REVISION "21.01")
azsphere_configure_api(TARGET_API_SET "8")

include_directories(./
					mbedtls/include)



add_compile_definitions(MBEDTLS_CONFIG_FILE="mbedtls_user_config.h")


link_directories(out/ARM-Debug/mbedtls/library)

add_subdirectory (mbedtls)

# Create executable
add_executable (${PROJECT_NAME} main.c)
target_link_libraries (${PROJECT_NAME} applibs pthread gcc_s c mbedtls mbedcrypto mbedx509)

azsphere_target_add_image_package(${PROJECT_NAME} RESOURCE_FILES "GlobalSignRootCA.crt")

