#include "Config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "Hook.h"
#include "Logger.h"

/* TODO: cleanup memory */

namespace armhook {

Config* Config::kInstance_ = NULL;

Config* Config::Instance()
{
	if (!kInstance_)
		kInstance_ = new Config();

	return kInstance_;
}

Config::Config()
	: root_(NULL)
	, helper_(NULL)
{}

bool Config::Parse(const char *file)
{
	FILE *f = fopen(file, "rb");
	if (!f) {
		LOG_ERROR("couldn't open file: %s", file);
		return false;
	}

	fseek(f, 0, SEEK_END);
	unsigned int fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *input = (char *)calloc(1, fsize + 1);
	fread(input, fsize, 1, f);
	fclose(f);

	input[fsize] = 0;

	root_ = json_loads(input, 0, &last_error_);
	if (!root_) {
		LOG_ERROR("json_loads() failed, error: "
			"text: %s, source: %s, line: %d, column: %d, pos: %d",
			last_error_.text, last_error_.source, last_error_.line,
			last_error_.column, last_error_.position);
		return false;
	}

	if (!json_is_object(root_)) {
		LOG_ERROR("root element of config must be an object");
		return false;
	}

	json_t *settings = NULL;
	if ((settings = GetJSONObject(root_, "settings")) == NULL ||
		(helper_ = GetJSONString(settings, "helper")) == NULL ||
		(libc_ = GetJSONString(settings, "libc")) == NULL) {
		LOG_ERROR("invalid 'settings' section");
		return false;
	}

	json_t *hooks = GetJSONArray(root_, "hooks");
	if (!hooks) {
		LOG_ERROR("invalid 'hooks' section");
		return false;
	}

	for (size_t i=0; i<json_array_size(hooks); i++) {
		json_t *data = json_array_get(hooks, i);
		if (!json_is_object(data)) {
			LOG_ERROR("'hooks' element %d isn't an object", i);
			return false;
		}

		const char *handler = GetJSONString(data, "handler");
		const char *library = GetJSONString(data, "library");

		if (!handler || !library) {
			LOG_ERROR("invalid 'hooks' element: %d", i);
			return false;
		}

		json_int_t relative = GetJSONInteger(data, "relative");
		json_int_t absolute = GetJSONInteger(data, "absolute");

		if (relative) {
			const char *base = GetJSONString(data, "base");
			if (!base) {
				LOG_ERROR("property 'relative' requires "
					"property 'base', element: %d", i);
				return false;
			}

			hooks_.push_back(new Hook(relative, base, handler,
				library));
		} else if (absolute) {
			hooks_.push_back(new Hook(absolute, handler, library));
		} else {
			LOG_ERROR("either 'relative' or 'absolute' property "
				"must be present, element %d", i);
			return false;
		}
	}

	LOG_INFO("found %d hook(s) in config file", hooks_.size());

	return true;
}

const char* Config::GetJSONString(json_t *obj, const char *name)
{
	json_t *str = json_object_get(obj, name);
	if (!str) {
		LOG_INFO("property: '%s' is not present", name);
		return NULL;
	}

	if (!json_is_string(str)) {
		LOG_WARN("proprety: '%s' is not a string", name);
		return NULL;
	}

	return json_string_value(str);
}

json_t* Config::GetJSONObject(json_t *obj, const char *name)
{
	json_t *tmp = json_object_get(obj, name);
	if (!tmp) {
		LOG_INFO("object: '%s' is not present", name);
		return NULL;
	}

	if (!json_is_object(tmp)) {
		LOG_WARN("'%s' is not an object", name);
		return NULL;
	}

	return tmp;
}

json_t* Config::GetJSONArray(json_t *obj, const char *name)
{
	json_t *array = json_object_get(obj, name);
	if (!array) {
		LOG_INFO("array: '%s' is not present", name);
		return NULL;
	}

	if (!json_is_array(array)) {
		LOG_WARN("'%s' is not an array", name);
		return NULL;
	}

	return array;
}

json_int_t Config::GetJSONInteger(json_t *obj, const char *name)
{
	json_t *value = json_object_get(obj, name);
	if (!value) {
		LOG_INFO("property: '%s' is not present", name);
		return 0;
	}

	if (!json_is_integer(value)) {
		LOG_WARN("'%s' is not an integer", name);
		return 0;
	}

	return json_integer_value(value);
}

} /* namespace armhook */
