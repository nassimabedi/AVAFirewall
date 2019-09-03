from file_handler import ReadJson
import socket
from avalogger.core import AvaLogger

confs = {"name": "AVAFirewall", "path":
         "/var/log/avapot/AVAFirewall_error.log", "level": "info"}
logger = AvaLogger.register(confs)


class AVAFirewallException(Exception):

    def __init__(self, msg=''):
        logger.log(msg)
        self.msg = msg

    def __str__(self):
        return self.msg


class AVAFirewallErrorHandling(AVAFirewallException):

    def __init__(self):
        self.msg = ''
        self.result = True
        self.obj_json = ReadJson("config.json")
        self.ip_version = self.obj_json.get_ip_version()
        self.err_code = ReadJson("error_code.json")

    def check_ip(self, ip):
        try:
            # test for IPv4
            socket.inet_pton(socket.AF_INET, ip)
        except socket.error:
            try:
                # test for IPv6
                socket.inet_pton(socket.AF_INET6, ip)
            except socket.error:
                self.msg = self.err_code.get_err("501")
                self.result = False
                logger.log(self.msg['msg'])
                print(ip, " is not valid")

        return {'result': self.result, 'msg': self.msg}

    def check_port(self, port):
        if not port.isdigit() and port < 1023 and port > 65535:
            self.result = False
            self.msg = self.err_code.get_err("502")
            logger.log(self.msg['msg'])
        return {'result': self.result, 'msg': self.msg}

    def check_mandatory_list(self, *args, **kargs):
        for element in args:
            if element not in kargs:
                self.result = False
                self.msg = self.err_code.get_err("505")
                logger.log(self.msg['msg'])
        return {'result': self.result, 'msg': self.msg}

    def check_mandatory_table(self, **kargs):
        if 'table_name' not in kargs:
            print kargs
            print '1111111111111111111111'
            self.result = False
            self.msg = self.err_code.get_err("503")
        else:
            print '2222222222222222222'
            result = self.check_table_name(kargs['table_name'])
            self.result = result['result']
            self.msg = result['msg']

        return {'result': self.result, 'msg': self.msg}

    def check_mandatory_chain(self, **kargs):
        if 'goto' not in kargs:
            self.result = False
            self.msg = self.err_code.get_err("504")
            logger.log(self.msg['msg'])
        return {'result': self.result, 'msg': self.msg}

    def check_table_name(self, table_name):
        # 505
        # obj_json = ReadJson("config.json")
        # ip_version = self.obj_json.get_ip_version()
        if self.ip_version == 'IPV4':
            if table_name not in ['FILTER', 'NAT', 'MANGLE', 'RAW']:
                self.result = False
                self.msg = self.err_code.get_err("506")
                logger.log(self.msg['msg'])
        elif self.ip_version == 'IPV6':
            if table_name not in ['FILTER', 'SECURITY', 'MANGLE', 'RAW']:
                self.result = False
                self.msg = self.err_code.get_err("506")
                logger.log(self.msg['msg'])

        return {'result': self.result, 'msg': self.msg}

    def public_iptable_error_handling(self, **kwargs):
        check_ip = check_port = {}
        check_port['result'] = check_ip['result'] = True
        check_table = self.check_mandatory_table(**kwargs)
        if check_table['result']:
            check_chain = self.check_mandatory_chain(**kwargs)
            if check_chain['result']:
                if 'source' in kwargs:
                    check_ip = self.check_ip(kwargs['source'])
                    if check_ip['result']:
                        if 'port' in kwargs:
                            check_port = self.check_port(kwargs['port'])
                            if check_port['result'] is False:
                                self.result = False
                                self.msg = check_port['msg']
                                logger.log(self.msg['msg'])
                    else:
                        self.result = False
                        self.msg = check_ip['msg']
                        logger.log(self.msg['msg'])
            else:
                self.result = False
                self.msg = check_chain['msg']
                logger.log(self.msg['msg'])

        else:
            self.result = False
            self.msg = check_table['msg']
            logger.log(self.msg['msg'])

        return {'result': self.result, 'msg': self.msg}

    def check_chain(self):
        pass


if __name__ == '__main__':
    obj_err = AVAFirewallErrorHandling()
    result = obj_err.check_ip()
    print result
