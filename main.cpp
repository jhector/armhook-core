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
	Elf(Addr) loc = 0;
	int32_t res = 0, result = 1;
	uint32_t ret = 0;
	pid_t pid = -1;

	Process *proc = NULL;

	if (argc != 5) {
		printf("Usage: %s <pid> <libc name> <inject path> <sym>\n",
			argv[0]);
		goto fail;
	}

	pid = atoi(argv[1]);

	proc = new Process(pid);
	if (!proc) {
		goto fail;
	}

	if (!proc->Attach()) {
		LOG_ERROR("attach failed");
		goto fail;
	}

	LOG_INFO("successfully attached to pid: %d", pid);

	if (!proc->Init(argv[2])) {
		LOG_ERROR("failed to initialize process, with libc: %s",
			argv[2]);
		goto fail_detach;
	}

	if (!proc->Inject(std::string(argv[3]))) {
		LOG_ERROR("failed to inject: %s", argv[3]);
		goto fail_detach;
	}

	if (!proc->Resolve(std::string(argv[3]), std::string(argv[4]), loc)) {
		LOG_ERROR("failed to resolve: %s in %s", argv[4], argv[3]);
		goto fail_detach;
	}

	if ((res = proc->Execute(loc, NULL, 0, &ret)) < 0) {
		LOG_ERROR("Execution failed: %d", res);
		goto fail_detach;
	}

	LOG_INFO("Got return value: 0x%08x", ret);

	result = 0;

fail_detach:
	proc->Detach();
	delete proc;

fail:
	return result;
}
