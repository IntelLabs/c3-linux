/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Copyright (C) 2024 Intel Corporation */
#ifndef _ASM_X86_LINUX_CC_TRY_BOX_H
#define _ASM_X86_LINUX_CC_TRY_BOX_H

#define _CC_GLOBALS_NO_INCLUDES_

#define _CC_GLOBALS_NO_INCLUDES_
#if __has_include("../../../../../../../malloc/try_box.h")
// Building as c3-simulator submodule
#include "../../../../../../../malloc/try_box.h"
#elif __has_include("../../../../../cc/malloc/try_box.h")
// Building with c3-simulator in kernel repo at ./cc
#include "../../../../../cc/malloc/try_box.h"
#elif __has_include("../../../../../../cc/malloc/try_box.h")
// Building with c3-simulator and c3-linux in same folder
#include "../../../../../../cc/malloc/try_box.h"
#endif

#endif // _ASM_X86_LINUX_CC_TRY_BOX_H