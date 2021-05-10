#ifndef SLIST_H
#define SLIST_H

#include <stdbool.h>
#include <sys/types.h>

struct slist;

struct slist *slist_create(void);
struct slist *slist_clone(const struct slist *slist);
void slist_destroy(struct slist *slist);

void slist_append(struct slist *slist, const char *str);

const char *slist_get(const struct slist *slist, size_t index);

size_t slist_len(const struct slist *slist);

bool slist_has(const struct slist *slist, const char *str);

char *slist_join(const struct slist *slist, char delim);
struct slist *slist_split(const char *str, char delim);

#endif


    
