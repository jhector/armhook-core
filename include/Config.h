#ifndef ARMHOOK_CONFIG_H_
#define ARMHOOK_CONFIG_H_

#include <vector>

#include "jansson.h"

namespace armhook {

class Hook;

class Config
{
public:
	static Config* Instance();

	bool Parse(const char *file);

	const char *helper() const { return helper_; }
	const char *libc() const { return libc_; }

	const std::vector<Hook*>& hooks() const { return hooks_; }

private:
	static Config *kInstance_;

	Config();

	const char *GetJSONString(json_t *obj, const char *name);

	json_t *GetJSONObject(json_t *obj, const char *name);
	json_t *GetJSONArray(json_t *obj, const char *name);

	json_int_t GetJSONInteger(json_t *obj, const char *name);

	json_t *root_;
	json_error_t last_error_;

	const char *helper_;
	const char *libc_;

	std::vector<Hook*> hooks_;
};

} /* namespace armhook */

#endif /* ARMHOOK_CONFIG_H_ */
