/*
 * Copyright (c) 2015 Intel corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file Software interrupts utility code - ARC implementation
 */

#include <zephyr/kernel.h>
#include <zephyr/irq_offload.h>

static irq_offload_routine_t offload_routine;
static const void *offload_param;

/* Called by trap_s exception handler */
void z_irq_do_offload(void)
{
	offload_routine(offload_param);
}

void arch_irq_offload(irq_offload_routine_t routine, const void *parameter)
{

	offload_routine = routine;
	offload_param = parameter;

	__asm__ volatile ("trap_s %[id]"
		:
		: [id] "i"(_TRAP_S_SCALL_IRQ_OFFLOAD) : );

}
