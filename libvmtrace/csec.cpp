#include <libvmi/libvmi.h>
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>
#include <plugins/Plugins.hpp>

using namespace libvmtrace;
using namespace libvmtrace::util;

std::shared_ptr<SystemMonitor> _sm;
std::shared_ptr<LinuxVM> _linux;

static bool interrupted = false;
static void close_handler(int sig)
{
	if (sig == SIGSEGV) 
	{
		_linux = nullptr;
		_sm = nullptr;
	}

	interrupted = true;
}

int main(int argc, char* argv[]) 
{
	bool prevent = false;

	if (argc == 1)
	{
		std::cout << argv[0] << " <vmname>" << " [1]" << std::endl;
		return -1;
	}

	if (argc == 3)
		prevent = atoi(argv[2]);

	std::string vm_id = argv[1];

	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);

	_sm = std::make_shared<SystemMonitor>(vm_id, true);
	_linux = std::make_shared<LinuxVM>(_sm);
	ProcessCache pc(*_linux);

	Log* log = new Log();
	log->RegisterLogger(new StdoutLogger(false));

	SyscallLogger sl(vm_id, *_linux, pc, *log, prevent, true, false);
	Controller c;
	c.RegisterPlugin(sl);

	std::vector<std::string> calls_to_log;
	calls_to_log.push_back("175");
	calls_to_log.push_back("313");
	
	c.ExecuteCommand("SyscallLogger", "Trace", calls_to_log, "0", vm_id);

	while(!interrupted) 
		sleep(1);

	return 0;
}
