#include "Logger.h"

#include <cstdio>

#ifdef __ANDROID__
#define dprintf fdprintf
#define vdprintf vfdprintf
#endif

using namespace armhook;

Logger *Logger::instance_ = NULL;

Logger *Logger::Instance(LogLevel lvl /* = kMsgNone */, int fd /* = -1 */)
{
	if (!instance_)
		instance_ = new Logger(lvl, fd);

	return instance_;
}

Logger::Logger(LogLevel lvl, int fd)
	: log_fd_(fd)
	, log_level_(lvl)
{
}

void Logger::log(LogLevel lvl, const char *file, uint32_t line,
	const char *fmt, ...)
{
	if (log_level_ < lvl || log_fd_ < 0)
		return;

	va_list args;
	va_start(args, fmt);

	char *msg = NULL;
	switch (lvl) {
	case kMsgNone: return;
	case kMsgError: msg = "ERROR"; break;
	case kMsgWarn: msg = "WARN"; break;
	case kMsgInfo: msg = "INFO"; break;
	case kMsgDebug: msg = "DEBUG"; break;
	}

	dprintf(log_fd_, "%s [%s:%d] ", msg, file, line);
	vdprintf(log_fd_, fmt, args);
	dprintf(log_fd_, "\n");

	va_end(args);
}
