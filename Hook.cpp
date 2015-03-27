#include "Hook.h"

#include <cstring>

#include "Process.h"
#include "Logger.h"

namespace armhook {

/* detour opcodes for arm and thumb mode */
uint8_t kArmDetour[] = {
	0x1f, 0x40, 0x2d, 0xe9, /* push {r0, r1, r2, r3, r4, lr} */
	0x02, 0x01, 0xa0, 0xe3, /* mov r0, 0x80000000 */
	0x30, 0xff, 0x2f, 0xe1, /* blx r0 */
};

uint8_t kThumbDetour[] = {
	0x1f, 0xb5, /* push {r0, r1, r2, r3, r4, lr} */
	0x08, 0x20, /* mov r0, 0x8 */
	0x00, 0x07, /* lsl r0, r0, 28 */
	0x80, 0x47, /* blx r0 */
};

uint8_t kThumbNops[] = {
	0x00, 0x1c, /* mov r0, r0 */
	0x00, 0x1c, /* mov r0, r0 */
	0x00, 0x1c, /* mov r0, r0 */
	0x00, 0x1c, /* mov r0, r0 */
};


Hook::Hook(uint32_t abs, const char *handler, const char *lib)
	: relative_(false)
	, handler_(handler)
	, library_(lib)
	, base_(NULL)
	, location_(abs)
{
}

Hook::Hook(uint32_t relative, const char *base, const char *handler,
	const char *lib)
	: relative_(true)
	, handler_(handler)
	, library_(lib)
	, base_(base)
	, location_(relative)
{
}

bool Hook::GetDetour(uint8_t *out, uint8_t *size)
{
	if (*size < sizeof(kArmDetour) || *size < sizeof(kThumbDetour))
		return false;

	switch (location_ & 1) {
	case 1:
		memcpy((void*)out, kThumbDetour, sizeof(kThumbDetour));
		*size = sizeof(kThumbDetour);
		break;

	case 0:
		memcpy((void*)out, kArmDetour, sizeof(kArmDetour));
		*size = sizeof(kArmDetour);
		break;
	}

	return true;
}

bool Hook::GetNops(uint8_t *out, int8_t size)
{
	switch (location_ & 1) {
	case 1:
		if (size > sizeof(kThumbNops))
			size = sizeof(kThumbNops);

		memcpy((void*)out, kThumbNops, size);
		break;
	case 0:
		LOG_WARN("ARM nop instruction currently not present");
		return false;
		break;
	}

	return true;
}

} /* namespace armhook */
