#include "item.h"

#include "util.h"

void item_init(struct item *item)
{
    *item = (struct item) {
	.type = item_type_none,
	.data = NULL
    };
}

void item_deinit(struct item *item)
{
    if (item != NULL && item_is_set(item)) {
	ut_free(item->data);
	item_init(item);
    }
}

void item_set_file(struct item *item, const char *filename, bool sensitive)
{
    item_deinit(item);

    *item = (struct item) {
	.type = item_type_file,
	.sensitive = sensitive,
	.data = ut_strdup(filename)
    };
}

    
void item_set_value(struct item *item, const char *value, bool sensitive)
{
    item_set_value_n(item, value, strlen(value), sensitive);
}

void item_set_value_n(struct item *item, const char *value, size_t len,
		      bool sensitive)
{
    item_deinit(item);

    *item = (struct item) {
	.type = item_type_value,
	.sensitive = sensitive,
	.data = ut_strndup(value, len)
    };
}

#define SENSITIVE_DATA_STR "<hidden>"

const char *item_unsensitive_data(const struct item *item)
{
    if (item->sensitive)
	return SENSITIVE_DATA_STR;
    else
	return item->data;
}

void item_copy(const struct item *src_item, struct item *dst_item)
{
    item_deinit(dst_item);

    dst_item->type = src_item->type;

    if (src_item->type != item_type_none)
	dst_item->data = ut_strdup(src_item->data);
}

bool item_is_set(const struct item *item)
{
    return item->type != item_type_none;
}
