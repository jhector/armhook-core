#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "hook.h"

#define PAGE_START(P)   ((uint32_t)(P) & ~(PAGE_SIZE-1))
#define PAGE_END(P)     (((uint32_t)(P) + PAGE_SIZE - 1) & ~(PAGE_SIZE-1))

extern void trampoline(void);

void clearcache(char* begin, char *end);

uint8_t arm_return[] = {
	0x20, 0xf0, 0x9f, 0xe5, /* ldr pc, [pc, $0x20] */
	0x00, 0x00, 0x00, 0x00  /* padding */
};

uint8_t thumb_return[] = {
	0x30, 0xb4, /* push {r4, r5} */
	0x00, 0x4c, /* ldr r4, [pc, $0] */
	0x01, 0x94, /* str r4, [sp, $4] */
	0x10, 0xbd  /* pop {r4, pc} */
};

uint8_t thumb_nop[] = {
	0x00, 0x1c /* mov r0, r0 */
};

struct hook_mapping *hook_map;
struct saved_prolog *hook_prologs;

uint32_t hooks_limit = 0;
uint32_t hooks_counter = 0;

/* TODO: This function is used to determine the
 * the size of the 'trampoline' function due to relative relocations,
 * dirty way to do it, might change it later
 */
uint32_t dummy()
{
	return 0;
}

/* setup the trampoline at a given location */
void* setup_trampoline(void *loc)
{
	uint32_t size = (uint32_t)&dummy - (uint32_t)&trampoline;
	int32_t flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;

	void *map = mmap(loc, 0x2000, 7, flags, -1, 0);
	if (map == MAP_FAILED)
		return NULL;

	memcpy(map, (void*)&trampoline, size);

	return (void*)((uint32_t)loc ^ (uint32_t)size);
}

/* allocate memory with correct permissions */
int32_t allocate_structs(uint32_t max_hooks)
{
	if (max_hooks > 50)
		return -1;

	uint32_t size = max_hooks * sizeof(*hook_prologs);
	hook_prologs = mmap(0, size, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (hook_prologs == MAP_FAILED)
		return -2;

	size = max_hooks * sizeof(*hook_map);
	hook_map = mmap(0, size, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (hook_map == MAP_FAILED)
		return -3;

	return 0;
}

void* setup(void *loc, uint32_t max_hooks)
{
	uint32_t tramp = (uint32_t)setup_trampoline(loc);
	if ((tramp & (uint32_t)loc) != (uint32_t)loc)
		return NULL;

	if (allocate_structs(max_hooks) < 0)
		return NULL;

	hooks_limit = max_hooks;

	return (void*)tramp;
}

int32_t hook_add(hook_handler func, uint32_t loc, uint8_t bytes)
{
	if (hooks_counter >= hooks_limit)
		return -100;

	if (!hook_prologs || !hook_map)
		return -101;

	uint32_t max = sizeof(hook_prologs->prolog);
	uint32_t padding = 0;

	/* in case of thumb we might require more bytes for alignment */
        if (loc & 1)
                max -= (sizeof(thumb_return) + sizeof(thumb_nop));
        else
                max -= sizeof(arm_return);

        if (bytes > max)
                return -max;

	struct saved_prolog *prolog = hook_prologs;
	struct hook_mapping *mapping = hook_map;

	while (prolog->cont != 0x0)
		prolog++;

	while (mapping->lr != 0x0)
		mapping++;

	memcpy(prolog->prolog, (void*)(loc & 0xfffffffe), bytes);

	switch (loc & 1) {
	case 1:
		if ((bytes % 4) == 0) {
			padding = sizeof(thumb_nop);
			memcpy(prolog->prolog + bytes, thumb_nop,
				sizeof(thumb_nop));
		}
		thumb_return[2] = (uint8_t)((SIZE_SAVED - bytes -
			sizeof(thumb_return) + 2) / 4);
		memcpy(prolog->prolog + bytes + padding, thumb_return,
			sizeof(thumb_return));
		break;
	case 0:
		arm_return[0] = (uint8_t)(SIZE_SAVED -
			sizeof(arm_return) - bytes);
		memcpy(prolog->prolog + bytes, arm_return,
			sizeof(arm_return));
		break;
	}

	prolog->cont = loc + bytes;

	/* store the mapping */
	mapping->lr = loc + bytes;
	mapping->handler = func;
	mapping->prolog = (loc & 1) ? ((uint8_t*)prolog + 1) : prolog;

	return hooks_counter++;
}

int32_t hook_del()
{
	/* TODO: cleanup array */
	return -1;
}

void clearcache(char* begin, char *end)
{
	const int syscall = 0xf0002;
	asm volatile (
		"mov	 r0, %0\n"
		"mov	 r1, %1\n"
		"mov	 r7, %2\n"
		"mov     r2, #0x0\n"
		"svc     0x00000000\n"
		:
		:	"r" (begin), "r" (end), "r" (syscall)
		:	"r0", "r1", "r7"
		);
}
