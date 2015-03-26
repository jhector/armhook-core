#ifndef ARMHOOK_LOGGER_H_
#define ARMHOOK_LOGGER_H_

#include <stdint.h>
#include <cstdarg>

#define LOG_MSG(lvl, ...) \
	Logger::Instance()->log(lvl, __FILE__, __LINE__, __VA_ARGS__);

#define LOG_ERROR(...) \
	LOG_MSG(Logger::kMsgError,__VA_ARGS__)

#define LOG_WARN(...) \
	LOG_MSG(Logger::kMsgWarn, __VA_ARGS__)

#define LOG_INFO(...) \
	LOG_MSG(Logger::kMsgInfo, __VA_ARGS__)

#define LOG_DEBUG(...) \
	LOG_MSG(Logger::kMsgDebug, __VA_ARGS__)

namespace armhook {

class Logger
{
public:
	typedef enum {
		kMsgNone = 0,
		kMsgError,
		kMsgWarn,
		kMsgInfo,
		kMsgDebug
	} LogLevel;

	static Logger* Instance(LogLevel lvl = kMsgNone, int fd = -1);

	void log(LogLevel lvl, const char *file, uint32_t line,
		const char *fmt, ...);

private:
	static Logger *instance_;

	Logger(LogLevel lvl, int fd);

	int log_fd_;
	LogLevel log_level_;
};

} /* armhook */

#endif /* ARMHOOK_LOGGER_H_ */
