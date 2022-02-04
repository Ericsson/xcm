#include "xcm_version.h"

unsigned int xcm_version_major(void)
{
    return XCM_VERSION_MAJOR;
}

unsigned int xcm_version_minor(void)
{
    return XCM_VERSION_MINOR;
}

unsigned int xcm_version_patch(void)
{
    return XCM_VERSION_PATCH;
}

const char *xcm_version(void)
{
    return XCM_VERSION;
}

unsigned int xcm_version_api_major(void)
{
    return XCM_VERSION_API_MAJOR;
}

unsigned int xcm_version_api_minor(void)
{
    return XCM_VERSION_API_MINOR;
}

const char *xcm_version_api(void)
{
    return XCM_VERSION_API;
}
