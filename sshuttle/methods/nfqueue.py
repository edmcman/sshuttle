import struct
from sshuttle.firewall import subnet_weight
from sshuttle.helpers import family_to_string
from sshuttle.linux import ipt, ipt_chain_exists
from sshuttle.methods import BaseMethod
from sshuttle.helpers import debug1, debug2, debug3, Fatal, which

import netfilterqueue
import threading


import socket
import os


IP_TRANSPARENT = 19
IP_ORIGDSTADDR = 20
IP_RECVORIGDSTADDR = IP_ORIGDSTADDR
SOL_IPV6 = 41
IPV6_ORIGDSTADDR = 74
IPV6_RECVORIGDSTADDR = IPV6_ORIGDSTADDR


def recv_udp(listener, bufsize):
    debug3('Accept UDP python using recvmsg.')
    data, ancdata, _, srcip = listener.recvmsg(
        4096, socket.CMSG_SPACE(24))
    dstip = None
    family = None
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_IP and cmsg_type == IP_ORIGDSTADDR:
            family, port = struct.unpack('=HH', cmsg_data[0:4])
            port = socket.htons(port)
            if family == socket.AF_INET:
                start = 4
                length = 4
            else:
                raise Fatal("Unsupported socket type '%s'" % family)
            ip = socket.inet_ntop(family, cmsg_data[start:start + length])
            dstip = (ip, port)
            break
        elif cmsg_level == SOL_IPV6 and cmsg_type == IPV6_ORIGDSTADDR:
            family, port = struct.unpack('=HH', cmsg_data[0:4])
            port = socket.htons(port)
            if family == socket.AF_INET6:
                start = 8
                length = 16
            else:
                raise Fatal("Unsupported socket type '%s'" % family)
            ip = socket.inet_ntop(family, cmsg_data[start:start + length])
            dstip = (ip, port)
            break
    return (srcip, dstip, data)


class Method(BaseMethod):

    def get_supported_features(self):
        result = super(Method, self).get_supported_features()
        result.ipv6 = True
        result.udp = True
        result.dns = True
        return result

    def get_tcp_dstip(self, sock):
        return sock.getsockname()

    def recv_udp(self, udp_listener, bufsize):
        srcip, dstip, data = recv_udp(udp_listener, bufsize)
        if not dstip:
            debug1(
                "-- ignored UDP from %r: "
                "couldn't determine destination IP address\n" % (srcip,))
            return None
        return srcip, dstip, data

    def setsockopt_error(self, e):
        """The nfqueue method needs root permissions to successfully
        use the nfqueue library."""
        raise Fatal("Insufficient permissions for nfqueue method.\n"
                    "Your effective UID is %d, not 0. Try rerunning as root.\n"
                    % os.geteuid())

    def send_udp(self, sock, srcip, dstip, data):
        if not srcip:
            debug1(
                "-- ignored UDP to %r: "
                "couldn't determine source IP address\n" % (dstip,))
            return
        sender = socket.socket(sock.family, socket.SOCK_DGRAM)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sender.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        except PermissionError as e:
            self.setsockopt_error(e)
        sender.bind(srcip)
        sender.sendto(data, dstip)
        sender.close()

    def setup_worker(self, tmark):

        if hasattr(self, "worker_thread"):
            debug3("Not creating duplicate worker thread")
            return

        def queue_worker():
            def print_and_accept(pkt):
                debug1(str(pkt))
                pkt.accept()

            nfqueue = netfilterqueue.NetfilterQueue()
            nfqueue.bind(tmark, print_and_accept)
            s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                nfqueue.run_socket(s)
            except KeyboardInterrupt:
                print('')

            debug1("queue_worker exiting")

            s.close()
            nfqueue.unbind()

        # Create a thread object that will execute the worker function
        self.worker_thread = threading.Thread(target=queue_worker)
        self.worker_thread.daemon = True
        self.worker_thread.start()
        #queue_worker()
        

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp,
                       user, group, tmark):
        
        self.setup_worker(int(tmark, 16))

        if family not in [socket.AF_INET, socket.AF_INET6]:
            raise Exception(
                'Address family "%s" unsupported by nfqueue method'
                % family_to_string(family))

        table = "filter"

        def _ipt(*args):
            return ipt(family, table, *args)

        def _ipt_proto_ports(proto, fport, lport):
            return proto + ('--dport', '%d:%d' % (fport, lport)) \
                if fport else proto

        filter_chain = 'sshuttle-f-%s' % port
        nfqueue_chain = 'sshuttle-n-%s' % port

        # basic cleanup/setup of chains
        self.restore_firewall(port, family, udp, user, group)

        _ipt('-N', nfqueue_chain)
        _ipt('-F', nfqueue_chain)
        _ipt('-N', filter_chain)
        _ipt('-F', filter_chain)
        _ipt('-I', 'OUTPUT', '1', '-j', filter_chain)

        _ipt('-A', nfqueue_chain, '-j', 'NFQUEUE', '--queue-num', tmark)
        # If not accepted, reject the connection.
        _ipt('-A', nfqueue_chain, '-j', 'REJECT')

        if False:
            for _, ip in [i for i in nslist if i[0] == family]:
                _ipt('-A', mark_chain, '-j', 'MARK', '--set-mark', tmark,
                    '--dest', '%s/32' % ip,
                    '-m', 'udp', '-p', 'udp', '--dport', '53')
                _ipt('-A', nfqueue_chain, '-j', 'TPROXY',
                    '--tproxy-mark', tmark,
                    '--dest', '%s/32' % ip,
                    '-m', 'udp', '-p', 'udp', '--dport', '53',
                    '--on-port', str(dnsport))

        # Don't have packets sent to any of our local IP addresses go
        # through the tproxy or mark chains (except DNS ones).
        #
        # Without this fix, if a large subnet is redirected through
        # sshuttle (i.e., 0/0), then the user may be unable to receive
        # UDP responses or connect to their own machine using an IP
        # besides (127.0.0.1). Prior to including these lines, the
        # documentation reminded the user to use -x to exclude their
        # own IP addresses to receive UDP responses if they are
        # redirecting a large subnet through sshuttle (i.e., 0/0).
        _ipt('-A', filter_chain, '-j', 'RETURN', '-m', 'addrtype',
             '--dst-type', 'LOCAL')
        
        for _, swidth, sexclude, snet, fport, lport \
                in sorted(subnets, key=subnet_weight, reverse=True):
            tcp_ports = ('-p', 'tcp')
            tcp_ports = _ipt_proto_ports(tcp_ports, fport, lport)

            if sexclude:
                _ipt('-A', filter_chain, '-j', 'RETURN',
                     '--dest', '%s/%s' % (snet, swidth),
                     '-m', 'tcp',
                     *tcp_ports)
            else:
                _ipt('-A', filter_chain, '-j', nfqueue_chain,
                     '--dest', '%s/%s' % (snet, swidth),
                     '-m', 'tcp',
                     *(tcp_ports))

            if False and udp:
                udp_ports = ('-p', 'udp')
                udp_ports = _ipt_proto_ports(udp_ports, fport, lport)

                if sexclude:
                    _ipt('-A', mark_chain, '-j', 'RETURN',
                         '--dest', '%s/%s' % (snet, swidth),
                         '-m', 'udp',
                         *udp_ports)
                    _ipt('-A', nfqueue_chain, '-j', 'RETURN',
                         '--dest', '%s/%s' % (snet, swidth),
                         '-m', 'udp',
                         *udp_ports)
                else:
                    _ipt('-A', mark_chain, '-j', 'MARK', '--set-mark', tmark,
                         '--dest', '%s/%s' % (snet, swidth),
                         '-m', 'udp',
                         *udp_ports)
                    _ipt('-A', nfqueue_chain, '-j', 'TPROXY',
                         '--tproxy-mark', tmark,
                         '--dest', '%s/%s' % (snet, swidth),
                         '-m', 'udp',
                         *(udp_ports + ('--on-port', str(port))))

    def restore_firewall(self, port, family, udp, user, group):
        if family not in [socket.AF_INET, socket.AF_INET6]:
            raise Exception(
                'Address family "%s" unsupported by tproxy method'
                % family_to_string(family))

        table = "filter"

        def _ipt(*args):
            return ipt(family, table, *args)

        filter_chain = 'sshuttle-f-%s' % port
        nfqueue_chain = 'sshuttle-n-%s' % port

        # basic cleanup/setup of chains
        if ipt_chain_exists(family, table, filter_chain):
            _ipt('-D', 'OUTPUT', '-j', filter_chain)
            _ipt('-F', filter_chain)
            _ipt('-X', filter_chain)

        if ipt_chain_exists(family, table, nfqueue_chain):
            _ipt('-F', nfqueue_chain)
            _ipt('-X', nfqueue_chain)


    def is_supported(self):

        try:
            import netfilterqueue
        except ImportError:
            debug2("nfqueue method not supported because the 'netfilterqueue' "
                   "module is missing.\n")
            return False

        if which("iptables") and which("ip6tables"):
            return True
        else:
            debug2("nfqueue method not supported because 'iptables' "
                "or 'ip6tables' commands are missing.\n")
            return False
