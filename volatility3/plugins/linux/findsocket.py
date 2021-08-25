from ctypes import addressof, pointer
import logging
from operator import sub
from typing import Generic, Iterable, List

from volatility3.framework import exceptions, interfaces, contexts
from volatility3.framework import renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins, objects
from volatility3.framework.renderers import format_hints
from volatility3.cli.volshell import generic
from volatility3.framework.symbols import linux
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
from enum import Enum

import ipaddress

vollog = logging.getLogger(__name__)

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False   

class FindSocket(plugins.PluginInterface):
    """Check system call table for hooks."""

    _required_framework_version = (1, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.VersionRequirement(name = 'linuxutils', component = linux.LinuxUtilities, version = (1, 0, 0)),
            requirements.SymbolTableRequirement(name = "vmlinux", description = "Linux kernel symbols")
        ]
    
    def reload_memory(self):
        """Reloads the memory from the memory dump."""

        ml = self.context.layers['memory_layer']
        ml.__init__(ml.context, ml.config_path, ml.name)
        
        pl = self.context.layers[self.config['primary']]
        pl._get_valid_table.cache_clear()

    @classmethod
    def get_ip4(cls, 
                ip_addr: int):
        return str(ipaddress.IPv4Address(big_to_little(ip_addr, 4))) 
    
    @classmethod
    def get_ip6(cls, 
                ip_addr: bytes):
        return str(ipaddress.IPv6Address(int.from_bytes(ip_addr, "big")))
    
    # TODO Write doc string
    @classmethod
    def netstat(cls, 
                context: interfaces.context.ContextInterface, 
                layer_name: str, 
                symbol_table_name: str, 
                config_path: str) -> Iterable[tuple]:
        """Lists all the tasks in the primary layer.
        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table_name: The name of the table containing the kernel symbols
        Yields:
            Process objects
        """

        vmlinux = contexts.Module(context, symbol_table_name, layer_name, 0)
        
        shell = generic.Volshell(context = context, config_path = config_path)
        shell._current_layer = layer_name
        dt = shell.display_type
        
        sfop = vmlinux.object_from_symbol("socket_file_ops")
        sfop_addr = sfop.vol.offset

        dfop = vmlinux.object_from_symbol("sockfs_dentry_operations")

        dfop_addr = dfop.vol.offset

        stats = []

        for task in pslist.PsList.list_tasks(context, layer_name, symbol_table_name):
            pid = task.pid
            ppid = task.parent.pid
            comm = utility.array_to_string(task.comm)

            for _, filp, full_path in linux.LinuxUtilities.files_descriptors_for_process(context, symbol_table_name, task):
                if filp.is_readable() and (filp.f_op == sfop_addr or filp.f_path.dentry.d_op == dfop):
                    socket = vmlinux.object("socket", offset = filp.f_inode - 48)
                    sk = socket.sk
                    inet_sock = vmlinux.object("inet_sock", offset = sk)
                    sk_common = sk.__getattr__("__sk_common")
                    protocol = utility.array_to_string(sk_common.skc_prot.dereference().name)
                    ref_count = sk_common.skc_refcnt.refs.counter
                    net_ref_count = sk_common.skc_net_refcnt 

                    port = big_to_little(sk_common.skc_dport, 2)
                    sport = big_to_little(inet_sock.inet_sport, 2)

                    # if '6' in protocol:
                    if protocol[-1] == '6':
                        ipaddr = cls.get_ip6(sk_common.skc_v6_daddr.in6_u.u6_addr8)
                        laddr = cls.get_ip6(sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8)
                        faddr = f"[{ipaddr}]:{str(port)}"
                        laddr = f"[{laddr}]:{str(sport)}"                           
                    else:
                        ipaddr = cls.get_ip4(sk_common.skc_daddr)
                        laddr = cls.get_ip4(sk_common.skc_rcv_saddr)
                        faddr = ipaddr + ':' + str(port)
                        laddr = laddr + ':' + str(sport)                            
                    
                    if "TCP" in protocol or "UNIX" in protocol and TcpStates.has_value(sk_common.skc_state):
                        state = TcpStates(sk_common.skc_state).name
                    else:
                        state = ""

                    ans = (f"{pid:<6}", f"{ppid:<6}",  f"{comm:<15}", f"{protocol:<8}", 
                           f"{laddr:<25}", f"{faddr:<25}", f"{state:<15}", f"{full_path:<25}")
                    stats.append(ans)

        stats.sort(key = lambda x: (x[3], int(x[4].split(':')[-1])))
        
        #(pid, ppid, comm, protocol, laddr, faddr, state, path)
        for stat in stats:
            yield stat

    @classmethod
    def netstatstr(cls, 
                   context: interfaces.context.ContextInterface, 
                   layer_name: str, 
                   symbol_table_name: str, 
                   config_path: str) -> Iterable[tuple]:
        
        vmlinux = contexts.Module(context, symbol_table_name, layer_name, 0)
        
        shell = generic.Volshell(context = context, config_path = config_path)
        shell._current_layer = layer_name
        dt = shell.display_type
        
        sfop = vmlinux.object_from_symbol("socket_file_ops")
        sfop_addr = sfop.vol.offset

        dfop = vmlinux.object_from_symbol("sockfs_dentry_operations")

        dfop_addr = dfop.vol.offset

        stats = []

        for task in pslist.PsList.list_tasks(context, layer_name, symbol_table_name):
            pid = task.pid
            ppid = task.parent.pid
            comm = utility.array_to_string(task.comm)

            for _, filp, full_path in linux.LinuxUtilities.files_descriptors_for_process(context, symbol_table_name, task):
                if filp.is_readable() and filp.f_op == sfop_addr:
                    socket = vmlinux.object("socket", offset = filp.f_inode - 48)
                    sk = socket.sk
                    inet_sock = vmlinux.object("inet_sock", offset = sk)
                    sk_common = sk.__getattr__("__sk_common")
                    protocol = utility.array_to_string(sk_common.skc_prot.dereference().name)

                    port = big_to_little(sk_common.skc_dport, 2)
                    sport = big_to_little(inet_sock.inet_sport, 2)

                    # if '6' in protocol:
                    if protocol[-1] == '6':
                        ipaddr = cls.get_ip6(sk_common.skc_v6_daddr.in6_u.u6_addr8)
                        laddr = cls.get_ip6(sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8)
                        faddr = f"[{ipaddr}]:{str(port)}"
                        laddr = f"[{laddr}]:{str(sport)}"                           
                    else:
                        ipaddr = cls.get_ip4(sk_common.skc_daddr)
                        laddr = cls.get_ip4(sk_common.skc_rcv_saddr)
                        faddr = ipaddr + ':' + str(port)
                        laddr = laddr + ':' + str(sport)                            
                    
                    if "TCP" in protocol or "UNIX" in protocol and TcpStates.has_value(sk_common.skc_state):
                        state = TcpStates(sk_common.skc_state).name
                    else:
                        state = ""

                    if 'UNIX' not in protocol:
                        ans = (f"{pid:<6} {ppid:<6} {comm:<15}", f"{protocol:<8}",f"{laddr:<25}", f"{faddr:<25} {state:<15}")
                    else:
                        ans = (f"{pid:<6} {ppid:<6} {comm:<15}", f"{protocol:<8}",f"{laddr:<15}",f"{full_path:<15} {state:<15}")
                    
                    stats.append(ans)
                    # yield ans

        # Sort by protocol and laddr port
        stats.sort(key = lambda x: (x[1], int(x[2].split(':')[-1])))
        
        #(pid, ppid, comm, protocol, laddr, faddr, state, path)
        for stat in stats:
            yield stat

    # TODO add constants for format like pid_format= "{0:<[len]}" for easier uniform formatting of each field
    def _generator(self):
        self.reload_memory()
        headPrinted = False
        # Printing header of non-unix protocols
        yield 0, (f"{'Pid':<6} {'Ppid':<6} {'Command':<15} {'Protocol':<7} {'Local Address':<25} {'Foreign Address':<25} {'State':<15}", "")

        for stat in self.netstatstr(self.context, self.config['primary'], self.config['vmlinux'], self.config_path):
            if not headPrinted and 'UNIX' in "".join(stat):
                # Printing header of unix protocols
                yield 0, (f"\n\n{'Pid':<6} {'Ppid':<6} {'Command':<15} {'Protocol':<8} {'Local Address':<15} {'Path':<15} {'State':<15}", "")
                headPrinted = True

            yield 0, (" ".join(stat), "")
    
    def run(self):
        return renderers.TreeGrid([("Net", str),("Stat", str)], self._generator())
        # return renderers.TreeGrid([(f"{'Pid':<6}", str), (f"{'Ppid':<6}", str), (f"{'Command':<15}", str), (f"{'Protocol':<7}", str), (f"{'Local Address':<25}", str), (f"{'Foreign Address':<25}", str), (f"{'State':<15}", str)], self._generator())

class TcpStates(Enum):
    ESTABLISHED  = 1
    SYN_SENT = 2
    SYN_RECEIVED = 3
    FIN_WAIT_1 = 4
    FIN_WAIT_2 = 5
    TIME_WAIT = 6
    CLOSE = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9
    LISTENING = 10
    CLOSING = 11
    MAX_STATES = 12

    @classmethod
    def has_value(cls, value):
        return value in cls._value2member_map_

# Converts big Endian to little Endian byte order
def big_to_little(num, size):
    return int.from_bytes(num.to_bytes(size, "big"), "little")
