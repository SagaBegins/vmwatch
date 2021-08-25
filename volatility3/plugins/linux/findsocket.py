from ctypes import addressof, pointer
import logging
from operator import sub
from typing import Generic, List

from volatility3.framework import exceptions, interfaces, contexts
from volatility3.framework import renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins, objects
from volatility3.framework.renderers import format_hints
from volatility3.cli.volshell import generic
from volatility3.framework.symbols import linux
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

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
    
        ml = self.context.layers['memory_layer']
        ml.__init__(ml.context, ml.config_path, ml.name)
        
        pl = self.context.layers[self.config['primary']]
        pl._get_valid_table.cache_clear()

    @classmethod
    def get_ip4(cls, ip_addr):
        return str(ipaddress.IPv4Address(big_to_little(ip_addr, 4))) 
    
    @classmethod
    def get_ip6(cls, ip_addr):
        return str(ipaddress.IPv6Address(int.from_bytes(ip_addr, "big")))
        # return str(ipaddress.ip_address(int.from_bytes(ip_addr, "big")))

    @classmethod
    def netstat(cls, context, layer, symbol_table, config_path):
        
        vmlinux = contexts.Module(context, symbol_table, layer, 0)
        
        shell = generic.Volshell(context = context, config_path = config_path)
        shell._current_layer = layer
        dt = shell.display_type
        
        sfop = vmlinux.object_from_symbol("socket_file_ops")
        sfop_addr = sfop.vol.offset

        dfop = vmlinux.object_from_symbol("sockfs_dentry_operations")

        dfop_addr = dfop.vol.offset

        stats = []

        for task in pslist.PsList.list_tasks(context, layer, symbol_table):
            pid = task.pid
            ppid = task.parent.pid
            comm = utility.array_to_string(task.comm)

            for _, filp, full_path in linux.LinuxUtilities.files_descriptors_for_process(context, symbol_table, task):
                # print(hex(filp.f_op), sfop)
                if filp.is_readable() and (filp.f_op == sfop_addr or filp.f_path.dentry.d_op == dfop):
                    socket = vmlinux.object("socket", offset = filp.f_inode - 48)
                    sk = socket.sk
                    inet_sock = vmlinux.object("inet_sock", offset = sk)
                    sk_common = sk.__getattr__("__sk_common")
                    protocol = utility.array_to_string(sk_common.skc_prot.dereference().name)
                    ref_count = sk_common.skc_refcnt.refs.counter
                    net_ref_count = sk_common.skc_net_refcnt 
                    # dt(sk_common)
                    # return
                    port = big_to_little(sk_common.skc_dport, 2)
                    sport = big_to_little(inet_sock.inet_sport, 2)

                    # if 'UNIX' in protocol:
                    #     dt(task.files.fd_array[fd_num].dereference().f_path.mnt.dereference().mnt_root.dereference())

                    if '6' in protocol:
                        ipaddr = cls.get_ip6(sk_common.skc_v6_daddr.in6_u.u6_addr8)
                        laddr = cls.get_ip6(sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8)
                        faddr = f"[{ipaddr}]:{str(port)}"
                        laddr = f"[{laddr}]:{str(sport)}"                           
                    else:
                        ipaddr = cls.get_ip4(sk_common.skc_daddr)
                        laddr = cls.get_ip4(sk_common.skc_rcv_saddr)
                        faddr = ipaddr + ':' + str(port)
                        laddr = laddr + ':' + str(sport)                            
                    
                    # TODO optimize this
                    if "TCP" in protocol or "UNIX" in protocol:
                        if sk_common.skc_state == 1:
                            state = "Established"

                        elif sk_common.skc_state == 2:
                            state = "Syn Sent"

                        elif sk_common.skc_state == 3:
                            state = "Syn Received"

                        elif sk_common.skc_state == 4:
                            state = "FIN wait 1"

                        elif sk_common.skc_state == 5:
                            state = "FIN wait 2"

                        elif sk_common.skc_state == 6:
                            state = "Time wait"

                        elif sk_common.skc_state == 7:
                            state = "Close"

                        elif sk_common.skc_state == 8:
                            state = "Close wait"

                        elif sk_common.skc_state == 9:
                            state = "Last Ack"

                        elif sk_common.skc_state == 10:
                            state = "Listening"

                        elif sk_common.skc_state == 11:
                            state = "Closing"

                        elif sk_common.skc_state == 12:
                            state = "Max States"  
                        else:
                            state = ""
                    else:
                        state = ""

                    ans = (f"{pid:<6}", f"{ppid:<6}",  f"{comm:<15}", f"{protocol:<8}", f"{laddr:<25}", f"{faddr:<25}", f"{state:<15}", f"{full_path:<25}")
                    stats.append(ans)

        stats.sort(key = lambda x: (x[3], int(x[4].split(':')[-1])))
        
        #(pid, ppid, comm, protocol, laddr, faddr, state, path)
        for stat in stats:
            yield stat

    @classmethod
    def netstatstr(cls, context, layer, symbol_table, config_path):
        
        vmlinux = contexts.Module(context, symbol_table, layer, 0)
        
        shell = generic.Volshell(context = context, config_path = config_path)
        shell._current_layer = layer
        dt = shell.display_type
        
        sfop = vmlinux.object_from_symbol("socket_file_ops")
        sfop_addr = sfop.vol.offset

        dfop = vmlinux.object_from_symbol("sockfs_dentry_operations")

        dfop_addr = dfop.vol.offset

        stats = []

        for task in pslist.PsList.list_tasks(context, layer, symbol_table):
            pid = task.pid
            ppid = task.parent.pid
            comm = utility.array_to_string(task.comm)

            for fd_num, filp, full_path in linux.LinuxUtilities.files_descriptors_for_process(context, symbol_table, task):
                if filp.is_readable() and filp.f_op == sfop_addr:
                    socket = vmlinux.object("socket", offset = filp.f_inode - 48)
                    sk = socket.sk
                    inet_sock = vmlinux.object("inet_sock", offset = sk)
                    sk_common = sk.__getattr__("__sk_common")
                    protocol = utility.array_to_string(sk_common.skc_prot.dereference().name)

                    port = big_to_little(sk_common.skc_dport, 2)
                    sport = big_to_little(inet_sock.inet_sport, 2)

                    # if 'UNIX' in protocol:
                    #     dt(task.files.fd_array[fd_num].dereference())

                    if '6' in protocol:
                        ipaddr = cls.get_ip6(sk_common.skc_v6_daddr.in6_u.u6_addr8)
                        laddr = cls.get_ip6(sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8)
                        faddr = f"[{ipaddr}]:{str(port)}"
                        laddr = f"[{laddr}]:{str(sport)}"                           
                    else:
                        ipaddr = cls.get_ip4(sk_common.skc_daddr)
                        laddr = cls.get_ip4(sk_common.skc_rcv_saddr)
                        faddr = ipaddr + ':' + str(port)
                        laddr = laddr + ':' + str(sport)                            
                    
                    # TODO optimize this
                    if "TCP" in protocol or "UNIX" in protocol:
                        if sk_common.skc_state == 1:
                            state = "Established"

                        elif sk_common.skc_state == 2:
                            state = "Syn Sent"

                        elif sk_common.skc_state == 3:
                            state = "Syn Received"

                        elif sk_common.skc_state == 4:
                            state = "FIN wait 1"

                        elif sk_common.skc_state == 5:
                            state = "FIN wait 2"

                        elif sk_common.skc_state == 6:
                            state = "Time wait"

                        elif sk_common.skc_state == 7:
                            state = "Close"

                        elif sk_common.skc_state == 8:
                            state = "Close wait"

                        elif sk_common.skc_state == 9:
                            state = "Last Ack"

                        elif sk_common.skc_state == 10:
                            state = "Listening"

                        elif sk_common.skc_state == 11:
                            state = "Closing"

                        elif sk_common.skc_state == 12:
                            state = "Max States"  
                        else:
                            state = ""
                    else:
                        state = ""

                    if 'UNIX' not in protocol:
                        ans = (f"{pid:<6} {ppid:<6} {comm:<15}",f"{protocol:<8}",f"{laddr:<25}",f"{faddr:<25} {state:<15}")
                    else:
                        ans = (f"{pid:<6} {ppid:<6} {comm:<15}", f"{protocol:<8}",f"{laddr:<15}",f"{full_path:<15} {state:<15}")
                    
                    stats.append(ans)
                    # yield ans

        stats.sort(key = lambda x: (x[1], int(x[2].split(':')[-1])))
        
        #(pid, ppid, comm, protocol, laddr, faddr, state, path)
        for stat in stats:
            yield stat

    def _generator(self):
        self.reload_memory()
        headPrinted = False
        yield 0, (f"{'Pid':<6} {'Ppid':<6} {'Command':<15} {'Protocol':<7} {'Local Address':<25} {'Foreign Address':<25} {'State':<15}", "")
        for stat in self.netstatstr(self.context, self.config['primary'], self.config['vmlinux'], self.config_path):
            # if 'UNIX' in stat[3]:
            #     yield (0, (stat[0], stat[1], stat[2], stat[3], stat[4], stat[-1], stat[-2]))
            # else:
            #     yield (0, stat[:-1])

            if not headPrinted and 'UNIX' in "".join(stat):
                yield 0, (f"\n\n{'Pid':<6} {'Ppid':<6} {'Command':<15} {'Protocol':<8} {'Local Address':<15} {'Path':<15} {'State':<15}", "")
                headPrinted = True

            yield 0, (" ".join(stat), "")
    
    # TODO add constants for format like pid_format= "{0:<[len]}" for easier uniform formatting of each field
    def run(self):
        return renderers.TreeGrid([("Net", str),("Stat", str)], self._generator())
        # return renderers.TreeGrid([(f"{'Pid':<6}", str), (f"{'Ppid':<6}", str), (f"{'Command':<15}", str), (f"{'Protocol':<7}", str), (f"{'Local Address':<25}", str), (f"{'Foreign Address':<25}", str), (f"{'State':<15}", str)], self._generator())



def big_to_little(num, size):
    return int.from_bytes(num.to_bytes(size, "big"), "little")