#ifndef ITEM_H
#define ITEM_H

#include <stdbool.h>
#include <sys/types.h>

enum item_type {
    item_type_none,
    item_type_file,
    item_type_value
};

struct item
{
    enum item_type type;
    bool sensitive;
    char *data;
};

void item_init(struct item *item);
void item_deinit(struct item *item);

void item_set_file(struct item *item, const char *filename, bool sensitive);
void item_set_value(struct item *item, const char *value, bool sensitive);
void item_set_value_n(struct item *item, const char *value, size_t len,
		      bool sensitive);

const char *item_unsensitive_data(const struct item *item);

void item_copy(const struct item *src_item, struct item *dst_item);

bool item_is_set(const struct item *item);

#endif
