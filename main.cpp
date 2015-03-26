#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <stdint.h>

#include <sys/mman.h>

#include "Process.h"
#include "Logger.h"
#include "Config.h"

using namespace armhook;

int main(int32_t argc, const char *argv[])
{
	Logger::Instance(Logger::kMsgDebug, 1);

	if (argc < 2) {
		printf("Arrrrgs...\n");
		return 0;
	}

	pid_t pid = atoi(argv[2]);

	Config *conf = Config::Instance();
	if (!conf->Parse(argv[1]))
		return 0;

	Process *proc = new Process(pid);
	if (!proc)
		return 0;

	if (!proc->Attach()) {
		LOG_ERROR("attach failed");
		return 0;
	}

	LOG_INFO("successfully attached to pid: %d", pid);

	if (!proc->Init(conf->libc())) {
		LOG_ERROR("failed to initialize process, with libc: %s",
			conf->libc());
		goto exit_detach;
	}

	if (!proc->PrepareHooking()) {
		LOG_ERROR("failed to prepare for hooking");
		goto exit_detach;
	}

	proc->InsertHooks(conf->hooks());

exit_detach:
	proc->Detach();
	delete proc;

	return 0;
}
