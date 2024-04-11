#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"
#include "attr.h"

#define MAX_ATTR_NAME_SIZE (64)
#define MAX_ATTR_VALUE_SIZE (512)

static void parse_str_attr(const char *s, char *name, char *value)
{
    const char *name_end = strchr(s, '=');
    if (name_end == NULL) {
	fprintf(stderr, "Invalid attribute format. '=' is missing.\n");
	exit(EXIT_FAILURE);
    }

    size_t name_len = name_end - s;
    if (name_len > MAX_ATTR_NAME_SIZE) {
	fprintf(stderr, "Attribute name too long.\n");
	exit(EXIT_FAILURE);
    }

    strncpy(name, s, name_len);
    name[name_len] = '\0';

    const char *value_part = &s[name_len + 1];
    if (strlen(value_part) > MAX_ATTR_VALUE_SIZE) {
	fprintf(stderr, "Attribute value too long.\n");
	exit(EXIT_FAILURE);
    }

    strcpy(value, value_part);
}

static void parse_int64_attr(const char *s, char *name, int64_t *value)
{
    char str_value[MAX_ATTR_VALUE_SIZE + 1];

    parse_str_attr(s, name, str_value);

    char *end;
    *value = strtol(str_value, &end, 10);

    if (end != (str_value + strlen(str_value))) {
	fprintf(stderr, "\"%s\" not an integer.\n", str_value);
	exit(EXIT_FAILURE);
    }
}

static void parse_double_attr(const char *s, char *name, double *value)
{
    char str_value[MAX_ATTR_VALUE_SIZE + 1];

    parse_str_attr(s, name, str_value);

    char *end;
    *value = strtod(str_value, &end);

    if (end != (str_value + strlen(str_value))) {
	fprintf(stderr, "\"%s\" not a double.\n", str_value);
	exit(EXIT_FAILURE);
    }
}

static void parse_bool_attr(const char *s, char *name, bool *value)
{
    char str_value[MAX_ATTR_VALUE_SIZE + 1];

    parse_str_attr(s, name, str_value);

    if (strcmp(str_value, "true") == 0)
	*value = true;
    else if (strcmp(str_value, "false") == 0)
	*value = false;
    else {
	fprintf(stderr, "Boolean attributes need to be either 'true' or "
		"'false'.\n");
	exit(EXIT_FAILURE);
    }
}

void attr_parse_bool(const char *s, struct xcm_attr_map *attrs)
{
    char name[MAX_ATTR_NAME_SIZE];
    bool value;

    parse_bool_attr(s, name, &value);

    xcm_attr_map_add_bool(attrs, name, value);
}

void attr_parse_int64(const char *s, struct xcm_attr_map *attrs)
{
    char name[MAX_ATTR_NAME_SIZE];
    int64_t value;

    parse_int64_attr(s, name, &value);

    xcm_attr_map_add_int64(attrs, name, value);
}

void attr_parse_double(const char *s, struct xcm_attr_map *attrs)
{
    char name[MAX_ATTR_NAME_SIZE];
    double value;

    parse_double_attr(s, name, &value);

    xcm_attr_map_add_double(attrs, name, value);
}

void attr_parse_str(const char *s, struct xcm_attr_map *attrs)
{
    char name[MAX_ATTR_NAME_SIZE];
    char value[MAX_ATTR_VALUE_SIZE];

    parse_str_attr(s, name, value);

    xcm_attr_map_add_str(attrs, name, value);
}

void attr_load_bin(const char *s, struct xcm_attr_map *attrs)
{
    char name[MAX_ATTR_NAME_SIZE];
    char filename[MAX_ATTR_VALUE_SIZE];

    parse_str_attr(s, name, filename);

    char *value;
    ssize_t rc = ut_load_file(filename, &value);

    if (rc < 0)
	ut_die("Error reading \"%s\"", filename);

    xcm_attr_map_add_bin(attrs, name, value, rc);
}
