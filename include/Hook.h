#ifndef ARMHOOK_HOOK_H_
#define ARMHOOK_HOOK_H_

#include <stdint.h>

namespace armhook {

class Process;

class Hook
{
public:
	Hook(uint32_t abs, const char *handler, const char *lib);
	Hook(uint32_t relative, const char *base, const char *handler,
		const char *lib);

	bool GetDetour(uint8_t *out, uint8_t *size);

	const char *handler() const { return handler_; }
	const char *library() const { return library_; }
	const char *base() const { return base_; }

	uint32_t location() const { return location_; }

	bool relative() const { return relative_; }

private:
	bool relative_;

	const char *handler_;
	const char *library_;
	const char *base_;

	uint32_t location_;
};

} /* namespace armhook */

#endif /* ARMHOOK_HOOK_H_ */
