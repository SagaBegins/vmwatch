from ctypes import addressof, pointer
import logging
from operator import sub
from typing import Generic, List, Protocol

from volatility3.framework import exceptions, interfaces, contexts
from volatility3.framework import renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins, objects
from volatility3.framework.renderers import format_hints
from volatility3.cli.volshell import generic
from volatility3.framework.objects import utility

import ipaddress

vollog = logging.getLogger(__name__)

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False


class Check_syscall(plugins.PluginInterface):
    """Check system call table for hooks."""

    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "vmlinux", description = "Linux kernel symbols")
        ]

    
    def reverse_ip(self, ip_addr):
        return '.'.join(str(ipaddress.ip_address(ip_addr)).split('.')[::-1])


    def _generator(self):
        
        vmlinux = contexts.Module(self.context, self.config['vmlinux'], self.config['primary'], 0)

        shell = generic.Volshell(context = self.context, config_path = self.config_path)
        shell._current_layer = self.config['primary']
        sfop = vmlinux.object_from_symbol("socket_file_ops")

        dt = shell.display_type
        dw = shell.display_words
        
        sfop_addr = str(sfop).split(' ')[4]
        tasks = list(vmlinux.object_from_symbol("init_task").tasks)

        for task in tasks:
            pid = task.pid

            comm = utility.array_to_string(task.comm)
        
            file = task.files
        
            for fd in file.fd_array:
                try:
                    if hex(fd.f_op) == sfop_addr:
                        socket = vmlinux.object("socket", offset = fd.f_inode - 48)
                        sk = socket.sk
                        inet_sock = vmlinux.object("inet_sock", offset = sk)
                        sk_common = sk.__getattr__("__sk_common")
                        # if(sk_common.skc_num != 0):
                        # dt(socket)
                        # dt(socket.wq.dereference())
                        # dt(socket.ops.dereference())
                        # dt(inet_sock)
                        # dt(sk_common.skc_prot.dereference())
                        # print("".join(map(chr, sk_common.skc_prot.dereference().name)))
                        prot = utility.array_to_string(sk_common.skc_prot.dereference().name)
                        # dt(sk.dereference())
                        ipaddr = self.reverse_ip(sk_common.skc_daddr)
                        laddr = self.reverse_ip(sk_common.skc_rcv_saddr)
                        
                        # dport = hex(sk_common.skc_dport)[2:]
                        # rdport = '0x' +dport[2:] + dport[:2]
                        # port = int(rdport, 16)
                        port = int.from_bytes(sk_common.skc_dport.to_bytes(2, "little")[::-1], "little")
                        
                        if sk_common.skc_state == 1:
                            state = "Established"
                        elif sk_common.skc_state == 10:
                            state = "Listening"
                        else:
                            state = ""
                        
                        faddr = ipaddr + ':' + str(port)
                        yield(0, (prot, pid, comm, laddr, faddr, state))
                        break
                except Exception as e:
                    continue

    def run(self):
        return renderers.TreeGrid([("Protocol", str), ("Pid", int), ("Command", str), ("Local Address", str), ("Foreign Address", str), ("State", str)], self._generator())
