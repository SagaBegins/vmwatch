# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Linux's /proc file system."""

import logging
from typing import List, Iterable

from volatility3.framework import contexts
from volatility3.framework import exceptions, renderers, constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import lsmod, findsocket, pslist
from volatility3.cli import volargparse
import time

vollog = logging.getLogger(__name__)
offset_format = "{0:<16}"
name_format = "{0:<20}"
size_format = "{0:<10}"

class Monitor(plugins.PluginInterface):
    """Lists loaded kernel modules."""
    
    CLI_NAME = 'volatility'

    _required_framework_version = (1, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.PluginRequirement(name = 'lsmod', plugin = lsmod.Lsmod, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'findsocket', plugin = findsocket.FindSocket, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.ListRequirement(name = 'time-interval',
                                         description = 'Time between each reads',
                                         element_type = int,
                                         default = [-1],
                                         optional = True),
            requirements.SymbolTableRequirement(name = "vmlinux", description = "Linux kernel symbols")
        ]

    def _generator(self):
        return

    def reload_memory(self):
        
        ml = self.context.layers['memory_layer']
        ml.__init__(ml.context, ml.config_path, ml.name)
        
        pl = self.context.layers[self.config['primary']]
        pl._get_valid_table.cache_clear()

    def get_conn(self):
        conn_set = set()
        for pid, _, name, protocol, laddr, faddr, _, full_path in findsocket.FindSocket.netstat(self.context, self.config['primary'], self.config['vmlinux'], self.config_path):
            l_to_f = f"{laddr.strip():<21}" +' > '+ f"{faddr.strip():<21}"
            pid_name = pid.strip()+'/'+name
            if 'UNIX' in protocol:
                conn_set.add(f"{protocol:<6} {l_to_f:<50} {pid_name:<20} {full_path}")
            else:
                conn_set.add(f"{protocol:<6} {l_to_f:<50} {pid_name}")

        return conn_set
    
    def get_proc(self):
        proc_set = set()
        for task in pslist.PsList.list_tasks(self.context, self.config['primary'], self.config['vmlinux']):
            pid = task.pid
            ppid = 0
            if task.parent:
                ppid = task.parent.pid
            name = utility.array_to_string(task.comm)
            proc_set.add(f"{pid:<6} {ppid:<6} {name:<}")

        return proc_set
    
    def get_kern(self):
        kern_set = set()
        for module in lsmod.Lsmod.list_modules(self.context, self.config['primary'], self.config['vmlinux']):
            name = utility.array_to_string(module.name)
            offset = module.vol.offset
            kern_set.add(f"{hex(offset):<15} {name:<}")

        return kern_set

    def get_missing(self, 
                    prev: set, 
                    curr: set) -> set:
        return prev - curr

    def get_added(self, 
                  prev: set, 
                  curr: set) -> set:
        return curr - prev
    
    def run(self):     
        """
        Write Doc string
        """
        first_iter = True
        time_interval = self.config['time-interval'][0]
        self.reload_memory()

        print(f"Logging Started {time.strftime('%d/%m/%Y %H:%M:%S',time.localtime())}. Interval {time_interval}s")
        print("Ctrl+C to exit\n", flush = True)
        try:
            while True:
                exec_start_time = time.time()

                curr_kernals = self.get_kern()
                curr_processes = self.get_proc()
                curr_connections = self.get_conn()

                if not first_iter:
                    stopped_processes = self.get_missing(prev_processes, curr_processes)
                    unloaded_kernals = self.get_missing(prev_kernals, curr_kernals)
                    closed_connections = self.get_missing(prev_connections, curr_connections)

                    started_processes = self.get_added(prev_processes, curr_processes)
                    loaded_kernals = self.get_added(prev_kernals, curr_kernals)
                    new_connections = self.get_added(prev_connections, curr_connections)

                    print(time.strftime("%d/%m/%Y %H:%M:%S", time.localtime()))
                    if len(stopped_processes) > 0 or len(started_processes) > 0:
                        print("Processes: (pid, ppid, name)")
                        writer(stopped_processes, started_processes)
                    else:
                        print("No process update.")
                    
                    if len(unloaded_kernals) > 0 or len(loaded_kernals) > 0:
                        print("Kernal Modules: (offset, name)")
                        writer(unloaded_kernals, loaded_kernals)
                    else:
                        print("No kernal module update.")

                    if len(closed_connections) > 0 or len(new_connections) > 0: 
                        print("Network Sockets: (Protocol, laddr -> faddr, pid/name)")
                        writer(closed_connections, new_connections)
                    else:
                        print("No connection update.")

                    print(flush = True)
                else:
                    first_iter = False

                # Copying current values 
                prev_kernals = {kernal for kernal in curr_kernals}
                prev_processes = {process for process in curr_processes}
                prev_connections = {connection for connection in curr_connections}
                
                self.reload_memory()
                exec_end_time = time.time()
                # Adjusting sleep time based on the execution duration
                sleep_time = time_interval - (exec_end_time-exec_start_time)
                if sleep_time > 0:
                    time.sleep(sleep_time)

        except KeyboardInterrupt as e:
            print(f"Logging Stopped {time.strftime('%d/%m/%Y %H:%M:%S',time.localtime())}.")
        
        return 

def writer(missing_set: set, 
           added_set: set):
    """
        Write Doc string
    """
    if len(missing_set) ==0 and len(added_set) == 0:
        return
    
    for deleted in missing_set:
        print("-", deleted)
    
    for added in added_set:
        print("+", added)
    
    print() 

