#include <string.h>

#include "util.h"

#include "slist.h"

struct slist
{
    char **elems;
    size_t len;
};

struct slist *slist_create(void)
{
    return ut_calloc(sizeof(struct slist));
}

struct slist *slist_clone(const struct slist *orig)
{
    struct slist *copy = slist_create();

    size_t i;
    for (i = 0; i < orig->len; i++)
	slist_append(copy, orig->elems[i]);

    return copy;
}

void slist_destroy(struct slist *slist)
{
    if (slist) {
	size_t i;
	for (i = 0; i < slist->len; i++)
	    ut_free(slist->elems[i]);
	ut_free(slist->elems);
	ut_free(slist);
    }
}

static void append(struct slist *slist, const char *str, size_t str_len)
{
    size_t new_len = slist->len + 1;

    slist->elems = ut_realloc(slist->elems, sizeof(char *) * new_len);

    if (str != NULL) {
	slist->elems[slist->len] = ut_calloc(str_len + 1);
	memcpy(slist->elems[slist->len], str, str_len);
    } else
	slist->elems[slist->len] = NULL;

    slist->len = new_len;
}

void slist_append(struct slist *slist, const char *str)
{
    append(slist, str, str != NULL ? strlen(str) : 0);
}

const char *slist_get(const struct slist *slist, size_t index)
{
    return slist->elems[index];
}

size_t slist_len(const struct slist *slist)
{
    return slist->len;
}

bool slist_has(const struct slist *slist, const char *str)
{
    size_t i;
    for (i = 0; i < slist->len; i++)
	if (strcmp(slist->elems[i], str) == 0)
	    return true;
    return false;
}

char *slist_join(const struct slist *slist, char delim)
{
    if (slist->len == 0)
	return ut_calloc(1);

    size_t buf_len = 0;

    size_t i;
    for (i = 0; i < slist->len; i++)
	buf_len += strlen(slist->elems[i]);

    /* for NUL and delimiters, if any */
    buf_len += slist->len;

    char *buf = ut_calloc(buf_len);

    for (i = 0; i < slist->len; i++) {
	if (i != 0)
	    buf[strlen(buf)] = delim;
	strcpy(buf + strlen(buf), slist->elems[i]);
    }

    return buf;
}

struct slist *slist_split(const char *str, char delim)
{
    struct slist *slist = slist_create();

    if (strlen(str) == 0)
	return slist;

    const char *left = str;

    for (;;) {
	char *end = strchrnul(left, delim);
	append(slist, left, end - left);
	if (*end == '\0')
	    return slist;
	left = end + 1;
    }
}
