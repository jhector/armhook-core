#ifndef ARMHOOK_LIB_HOOK_H
#define ARMHOOK_LIB_HOOK_H

#include <stdint.h>

#define SIZE_SAVED 4*10

struct hook_data {
	uint32_t cpsr;
	uint32_t r0, r1, r2, r3;
	uint32_t *sp;
	uint32_t skip_lr;
};

typedef int8_t (*hook_handler)(struct hook_data*);

struct __attribute__((packed)) saved_prolog {
	uint8_t prolog[SIZE_SAVED]; /* saved prolog bytes */
	uint32_t cont; /* address to continue hooked function */
};

struct __attribute__((packed)) hook_mapping {
	uint32_t lr;
	hook_handler handler;
	struct saved_prolog *prolog;
};

#endif /* ARMHOOK_LIB_HOOK_H */
