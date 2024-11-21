/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef UTEST_HUMAN_REPORT_H
#define UTEST_HUMAN_REPORT_H

#include "utestreport.h"

#include <stdio.h>

struct utest_report* utest_human_report_create(FILE* output, bool verbose,
					       bool color);

#endif
