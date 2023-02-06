#include "xcm_dns.h"

#include <regex.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#define DNS_MAX_LEN (253)
#define DNS_RE "^[a-z0-9\\-]+(\\.[a-z0-9\\-]+\\.?)*$"

bool xcm_dns_is_valid_name(const char *name)
{
    if (strlen(name) > DNS_MAX_LEN)
	return false;

    regex_t re;
    int rc = regcomp(&re, DNS_RE, REG_ICASE|REG_EXTENDED);

    if (rc != 0)
	ut_mem_exhausted();

    bool result;
    regmatch_t m;
    rc = regexec(&re, name, 1, &m, 0);
    if (rc == 0)
	result = true;
    else if (rc == REG_NOMATCH)
	result = false;
    else
	ut_fatal();

    regfree(&re);

    return result;
}

