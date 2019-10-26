/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef CTL_H
#define CTL_H

/**
 * This module terminates the UNIX domain socket-based control
 * interface (on the library side, in the process using XCM). The
 * control interface allows access to various socket-related state
 * from outside the process using XCM.
 */

#include "xcm.h"

struct ctl;

struct ctl *ctl_create(struct xcm_socket *socket);
void ctl_destroy(struct ctl *ctl, bool owner);
void ctl_process(struct ctl *ctl);

#endif
