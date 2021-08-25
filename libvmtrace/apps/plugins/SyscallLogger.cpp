#include <plugins/SyscallLogger.hpp>
#include <sys/LinuxVM.hpp>
#include <string.h>
#include <fstream>
#include <time.h>
#include <ctime>
#include <cmath>
#include <unistd.h>

using namespace rapidjson;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::system_clock;


namespace libvmtrace
{
	const std::string SyscallLogger::ExecuteCommand(const std::string command, 
					const std::vector<std::string> params,
					const std::string command_id,
					const std::string vm_id)
	{
		if(vm_id != _vm_id)
		{
			return "";
		}
	
		if(command == "Trace" && params.size() > 0)
		{
			for(auto x : params)
			{
				int nr = atoi(x.c_str());
				if (_events[nr] == NULL)
				{
					if(nr == 59) // exec does not return
					{	
						_events[nr] = new SyscallEvent(nr, *this, false, false, _json);
					}
					else
					{
						_events[nr] = new SyscallEvent(nr, *this, _return_value, false, _json);
					}

					_os.RegisterSyscall(*_events[nr]);
				}
			}
		}
		else if(command == "Untrace" && params.size() > 0)
		{
			for(auto x : params)
			{
				int nr = atoi(x.c_str());
				if(_events[nr] != nullptr)
				{
					_os.DeRegisterSyscall(*_events[nr]);
					delete _events[nr];
					_events[nr] = nullptr;
				}
			}
		}

		return "";
	}

	bool SyscallLogger::callback(const Event* ev, void* data)
	{
		const SyscallEvent* sev = dynamic_cast<const SyscallEvent*>(ev);
		LinuxVM *lvm = dynamic_cast<LinuxVM*> (&_os);
		
		if(!sev)
		{
			return  false;
		}
		SyscallBasic* s = (SyscallBasic*)data;


		std::string json = s->ToJson();

		Document document;
		document.Parse(json.c_str());
		Document::AllocatorType& allocator = document.GetAllocator();
		const int BUFFER_LEN = 10000;

		try
		{
			const Process& p = _pc.GetProcessFromDtb(s->GetDtb());
			std::string name = p.GetName();
			std::string pwd = p.GetPwd();

			document.AddMember("proc_name", Value(name.c_str(), allocator).Move(), allocator);
			document.AddMember("uid", p.GetUid(), allocator);

			document.AddMember("pwd",  Value(pwd.c_str(), allocator).Move(), allocator);
		}
		catch(...)
		{
			document.AddMember("proc_name", "ERR", allocator);
			document.AddMember("uid", 0, allocator);
			document.AddMember("pwd", "ERR", allocator);
		}
		
		const std::string USR_MODULE = "/usr/lib/modules/"; // len 17
		const std::string LIB_MODULE = "/lib/modules/"; // len 13

		if(s->GetNr() == 1)
		{
			Process p = lvm->GetCurrentProcess(s->GetRegisters().gs_base);
			// GetOpenFiles extracts file names from task_struct; the second
			// parameter is a filter that selects a specific file descriptor
			std::vector<OpenFile> ofv = lvm->GetOpenFiles(p, s->GetParameter(0));
			if(ofv.size()>0) 
			{ 
				std::string path = ofv[0].path; 
				document.AddMember("fileName",StringRef(path.c_str()),allocator);
			}
		}
		else if(s->GetNr() == 2)
		{
			std::string path = "EMPTY PATH";
			std::string pwd = "EMPTY PWD";
			if (document.HasMember("path"))
			    path = document["path"].GetString();
			if (document.HasMember("pwd"))
			    pwd = document["pwd"].GetString();

			std::string fullPath = path;
			if(!path.empty())
			{
				std::string tmp = path.substr(0,1);
				if(tmp.compare("/") != 0)
				{
					fullPath = pwd+"/"+path;
				}
			}

			Value sa;
			sa = StringRef(fullPath.c_str());
			document.AddMember("fullPath", sa, allocator);
		}
		else if(s->GetNr() == 175)
		{ 
			// When process uses init_module(void *image, unsigned long len, char *param)
			// it is paused and when the prevent flag is true the address is changed to prevent 
			// it being called. The image of the module is dumped in /root/modwatch/dumps/dump-[time-stamp].bin 

			std::cout << std::endl; 
			Process p = lvm->GetCurrentProcess(s->GetRegisters().gs_base);		
			
			auto _sm = lvm->GetSystemMonitor();
			const auto vm = _sm->Lock();

			unsigned long file_length = s->GetParameter(1);
			const addr_t param_pointer = s->GetParameter(2);
			char param[BUFFER_LEN];
			
			char* val = vmi_read_str_va(vm, param_pointer, p.GetPid());
			snprintf(param, BUFFER_LEN,"%s", val);

			document.AddMember("param", StringRef(param), allocator);
			document.AddMember("fileLength", file_length, allocator);
			
			if(_prevent) 
			{
				addr_t addr = 0;

				#ifdef INTROSPECT_PTREGS
					// Use LibVMI to write RSI in ptreg data structure
					addr_t offset = 0;
					vmi_get_kernel_struct_offset(vmi, "pt_regs", "si", &offset);
					addr_t rsi = s->GetRegisters().rdi + offset;
					int st = vmi_write_64_va(vmi, rsi, 0, &addr);
				#else
					// Use LibVMI to set VCPU register RSI (2nd argument) to 0
					int st = vmi_set_vcpureg(vmi, addr, RSI, 0);
				#endif
			}

			if(file_length) 
			{
				auto ts = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
				char image_name[1000];
				sprintf(image_name, "/root/modwatch/dumps/dump-%llu.bin", ts);

				std::ofstream outdata_image;
				outdata_image.open(image_name, std::ios::binary);
				
				unsigned long long times_to_loop = file_length/BUFFER_LEN;  					
				uint64_t* data;
				char* bin_data;
				const addr_t image_addr = s->GetParameter(0);
				addr_t next_addr = image_addr;

				// Begin writing dump
				for(unsigned long long i = 0; i < times_to_loop; ++i) 
				{
					data = new uint64_t[BUFFER_LEN];

					// Reading data of BUFFER_LEN into data
					vmi_read_va(vmi, next_addr, p.GetPid(), BUFFER_LEN, data, NULL);
					
					bin_data = static_cast<char*>(static_cast<void*>(data));

					outdata_image.write(bin_data, BUFFER_LEN);
					outdata_image.flush();

					next_addr += BUFFER_LEN;
					delete[] data;
				}

				// Getting the remainder
				unsigned long long remaining = file_length%BUFFER_LEN;
				data = new uint64_t[remaining];
				vmi_read_va(vmi, next_addr, p.GetPid(), remaining, data, NULL);
				
				bin_data = static_cast<char*>(static_cast<void*>(data));
				outdata_image.write(bin_data, remaining);

				outdata_image.flush();
				outdata_image.close();	
				// End writing dump			
			}
			
			_sm->Unlock();
		}
		else if(s->GetNr() == 313)
		{
			// When process uses finit_module(int fd, char *param, int flags)
			// it is paused and when the prevent flag is true and the module file is not in the usual directories,
			//  the address is changed to prevent it being called. 
			// The image of the module is dumped in /root/modwatch/dumps/dump-[time-stamp].bin 

			std::cout << std::endl;
			Process pr= lvm->GetCurrentProcess(s->GetRegisters().gs_base);
			std::vector<OpenFile> ofv = lvm->GetOpenFiles(pr, s->GetParameter(0));
			
			int fd = s->GetParameter(0);
			int flags = s->GetParameter(2);

			document.AddMember("fd", fd, allocator);
			document.AddMember("flags", flags, allocator);
			
			if(ofv.size()>0) 
			{ 	
				std::string path = ofv[0].path; 
				char path_buffer[BUFFER_LEN]; 
				sprintf(p, "%s", path.c_str()); // Helps prevent weird unicode from being printed

				document.AddMember("filename", StringRef(path_buffer), allocator);
				
				auto _sm = lvm->GetSystemMonitor();
				const auto vmi = _sm->Lock();	
				
				char param_buffer[BUFFER_LEN];
				addr_t param_addr = s->GetParameter(1);
				char *params = vmi_read_str_va(vmi, param_addr, pr.GetPid());
	
				if (params != NULL) 
				{
					snprintf(param_buffer, BUFFER_LEN,"%s", params);
					document.AddMember("param", StringRef(param_buffer.c_str()), allocator);
				}
				
				delete params;
				
				if(_prevent && !(USR_MODULE.compare(path.substr(0, strlen(USR_MODULE))) == 0 || LIB_MODULE.compare(path.substr(0, str(LIB_MODULE))) == 0) ) 
				{
					auto _sm = lvm->GetSystemMonitor(); 
					const auto vmi = _sm->Lock();
					addr_t addr = 0;
					#ifdef INTROSPECT_PTREGS
						// Use LibVMI to write RSI in ptreg data structure
						addr_t offset = 0;
						vmi_get_kernel_struct_offset(vmi, "pt_regs", "si", &offset);
						addr_t rsi = s->GetRegisters().rdi + offset;

						int st = vmi_write_64_va(vmi, rsi, 0, &addr);
					#else
						// Use LibVMI to set VCPU register RSI (2nd argument) to 0
						int st = vmi_set_vcpureg(vmi, addr, RSI, 0);
					#endif
					_sm->Unlock();
				}

				auto ts = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
				char dump_path[BUFFER_LEN];
				sprintf(dump_path, "/root/modwatch/dumps/dump-%llu.bin", ts);
				const char SCP_COMMAND[BUFFER_LEN];
				sprintf(SCP_COMMAND, SCP_MODULE_FILE_FORMAT, "scp 192.168.13.245:%s %s", path_buffer, dump_path)
				system(SCP_COMMAND);
			}
		}
	// #endif

		document.RemoveMember("dtb");
		document.RemoveMember("rsp");
		document.RemoveMember("rip");
		document.RemoveMember("syscall_name");
		document.RemoveMember("logtype");
		
		StringBuffer strbuf;
		Writer<StringBuffer> writer(strbuf);
		document.Accept(writer);

		_log.log(_vm_id, _log_name, strbuf.GetString());

		return false;
	}
}

