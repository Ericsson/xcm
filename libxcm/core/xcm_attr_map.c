#include "xcm_attr_map.h"

#include "util.h"

#include <string.h>
#include <sys/queue.h>

struct attr
{
    char *name;
    enum xcm_attr_type type;
    void *value;
    size_t value_len;

    LIST_ENTRY(attr) entry;
};

LIST_HEAD(attr_list, attr);

static void assert_valid_len(enum xcm_attr_type type, size_t value_len)
{
    switch(type) {
    case xcm_attr_type_bool:
	ut_assert(value_len == sizeof(bool));
	break;
    case xcm_attr_type_int64:
	ut_assert(value_len == sizeof(int64_t));
	break;
    case xcm_attr_type_double:
	ut_assert(value_len == sizeof(double));
	break;
    case xcm_attr_type_str:
    case xcm_attr_type_bin:
	break;
    }
}

static struct attr *attr_create(const char *name, enum xcm_attr_type type,
				const void *value, size_t value_len)

{
    assert_valid_len(type, value_len);

    struct attr *attr = ut_malloc(sizeof(struct attr));
    *attr = (struct attr) {
	.name = ut_strdup(name),
	.type = type,
	.value = ut_memdup(value, value_len),
	.value_len = value_len
    };

    return attr;
}

static void attr_destroy(struct attr *attr)
{
    if (attr != NULL) {
	ut_free(attr->name);
	ut_free(attr->value);
	ut_free(attr);
    }
}

struct xcm_attr_map
{
    struct attr_list attrs;
};

struct xcm_attr_map *xcm_attr_map_create(void)
{
    struct xcm_attr_map *attr_map = ut_malloc(sizeof(struct xcm_attr_map));

    LIST_INIT(&attr_map->attrs);

    return attr_map;
}

static void copy_attr_cb(const char *attr_name, enum xcm_attr_type attr_type,
			 const void *attr_value, size_t attr_value_len,
			 void *user)
{
    struct xcm_attr_map *copy = user;
    xcm_attr_map_add(copy, attr_name, attr_type, attr_value, attr_value_len);
}

struct xcm_attr_map *xcm_attr_map_clone(const struct xcm_attr_map *original)
{
    struct xcm_attr_map *copy = xcm_attr_map_create();

    xcm_attr_map_foreach(original, copy_attr_cb, copy);

    return copy;
}

static struct attr *lookup_attr(const struct xcm_attr_map *attr_map,
				const char *attr_name)
{
    struct attr *attr;
    LIST_FOREACH(attr, &attr_map->attrs, entry)
	if (strcmp(attr->name, attr_name) == 0)
	    return attr;
    return NULL;
}

static const struct attr *
lookup_attr_with_type(const struct xcm_attr_map *attr_map,
		      const char *attr_name,
		      enum xcm_attr_type type
)
{
    struct attr *attr;
    LIST_FOREACH(attr, &attr_map->attrs, entry)
	if (strcmp(attr->name, attr_name) == 0)
	    return attr->type == type ? attr : NULL;
    return NULL;
}

static const void *
lookup_value_with_type(const struct xcm_attr_map *attr_map,
		       const char *attr_name,
		       enum xcm_attr_type type)
{
    const struct attr *attr =
	lookup_attr_with_type(attr_map, attr_name, type);

    if (attr == NULL)
	return NULL;

    return attr->value;
}

void xcm_attr_map_add(struct xcm_attr_map *attr_map, const char *attr_name,
		      enum xcm_attr_type attr_type, const void *attr_value,
		      size_t attr_value_len)
{
    ut_assert(attr_name && attr_value);

    xcm_attr_map_del(attr_map, attr_name);

    struct attr *attr =
	attr_create(attr_name, attr_type, attr_value, attr_value_len);

    LIST_INSERT_HEAD(&attr_map->attrs, attr, entry);
}

void xcm_attr_map_add_bool(struct xcm_attr_map *attr_map,
			   const char *attr_name,
			   bool attr_value)
{
    xcm_attr_map_add(attr_map, attr_name, xcm_attr_type_bool, &attr_value,
		     sizeof(bool));
}

void xcm_attr_map_add_int64(struct xcm_attr_map *attr_map,
			   const char *attr_name,
			   int64_t attr_value)
{
    xcm_attr_map_add(attr_map, attr_name, xcm_attr_type_int64, &attr_value,
		     sizeof(int64_t));
}

void xcm_attr_map_add_double(struct xcm_attr_map *attr_map,
			     const char *attr_name,
			     double attr_value)
{
    xcm_attr_map_add(attr_map, attr_name, xcm_attr_type_double, &attr_value,
		     sizeof(double));
}

void xcm_attr_map_add_str(struct xcm_attr_map *attr_map,
			  const char *attr_name,
			  const char *attr_value)
{
    xcm_attr_map_add(attr_map, attr_name, xcm_attr_type_str, attr_value,
		     strlen(attr_value) + 1);
}

void xcm_attr_map_add_bin(struct xcm_attr_map *attr_map,
			  const char *attr_name, const void *attr_value,
			  size_t attr_value_len)
{
    xcm_attr_map_add(attr_map, attr_name, xcm_attr_type_bin, attr_value,
		     attr_value_len);
}

void xcm_attr_map_add_all(struct xcm_attr_map *dst_map,
			  const struct xcm_attr_map *src_map)
{
    if (dst_map != src_map)
	xcm_attr_map_foreach(src_map, copy_attr_cb, dst_map);
}

const void *xcm_attr_map_get(const struct xcm_attr_map *attr_map,
			     const char *attr_name,
			     enum xcm_attr_type *attr_type,
			     size_t *attr_value_len)
{
    struct attr *attr = lookup_attr(attr_map, attr_name);

    if (attr == NULL)
	return NULL;

    if (attr_type != NULL)
	*attr_type = attr->type;

    if (attr_value_len != NULL)
	*attr_value_len = attr->value_len;

    return attr->value;
}

const bool *xcm_attr_map_get_bool(const struct xcm_attr_map *attr_map,
				  const char *attr_name)
{
    return lookup_value_with_type(attr_map, attr_name, xcm_attr_type_bool);
}

const int64_t *xcm_attr_map_get_int64(const struct xcm_attr_map *attr_map,
				      const char *attr_name)
{
    return lookup_value_with_type(attr_map, attr_name, xcm_attr_type_int64);
}

const double *xcm_attr_map_get_double(const struct xcm_attr_map *attr_map,
				      const char *attr_name)
{
    return lookup_value_with_type(attr_map, attr_name, xcm_attr_type_double);
}

const char *xcm_attr_map_get_str(const struct xcm_attr_map *attr_map,
				 const char *attr_name)
{
    return lookup_value_with_type(attr_map, attr_name, xcm_attr_type_str);
}

const char *xcm_attr_map_get_bin(const struct xcm_attr_map *attr_map,
				 const char *attr_name)
{
    return lookup_value_with_type(attr_map, attr_name, xcm_attr_type_bin);
}

bool xcm_attr_map_exists(const struct xcm_attr_map *attr_map,
			 const char *attr_name)
{
    return lookup_attr(attr_map, attr_name) != NULL;
}

void xcm_attr_map_del(struct xcm_attr_map *attr_map, const char *attr_name)
{
    struct attr *attr = lookup_attr(attr_map, attr_name);

    if (attr != NULL) {
	LIST_REMOVE(attr, entry);
	attr_destroy(attr);
    }
}

size_t xcm_attr_map_size(const struct xcm_attr_map *attr_map)
{
    size_t count = 0;
    struct attr *attr;
    LIST_FOREACH(attr, &attr_map->attrs, entry)
	count++;
    return count;
}

void xcm_attr_map_foreach(const struct xcm_attr_map *attr_map,
			  xcm_attr_map_foreach_cb cb, void *user)
{
    struct attr *attr;
    LIST_FOREACH(attr, &attr_map->attrs, entry)
	cb(attr->name, attr->type, attr->value, attr->value_len, user);
}

bool xcm_attr_map_equal(const struct xcm_attr_map *attr_map_a,
			const struct xcm_attr_map *attr_map_b)
{
    size_t size_a = xcm_attr_map_size(attr_map_a);
    size_t size_b = xcm_attr_map_size(attr_map_b);

    if (size_a != size_b)
	return false;

    struct attr *attr_a;
    LIST_FOREACH(attr_a, &attr_map_a->attrs, entry) {
	const struct attr *attr_b =
	    lookup_attr_with_type(attr_map_b, attr_a->name, attr_a->type);
	if (attr_b == NULL)
	    return false;
	if (attr_a->value_len != attr_b->value_len)
	    return false;
	if (memcmp(attr_a->value, attr_b->value, attr_a->value_len) != 0)
	    return false;
    }

    return true;
}

void xcm_attr_map_destroy(struct xcm_attr_map *attr_map)
{
    if (attr_map != NULL) {
	struct attr *attr;
	while ((attr = LIST_FIRST(&attr_map->attrs)) != NULL) {
	    LIST_REMOVE(attr, entry);
	    attr_destroy(attr);
	}
	ut_free(attr_map);
    }
}
