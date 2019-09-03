from firewall_abstract import AbstractFirewall
from file_handler import ReadJson
from exception_handling import AVAFirewallException, AVAFirewallErrorHandling
import iptc
import sys

from avalogger.core import AvaLogger

confs = {"name": "AVAFirewall", "path":
         "/var/log/avapot/AVAFirewall.log", "level": "info"}
logger = AvaLogger.register(confs)


def my_exchandler(type, value, traceback):
    print(value)
    return {'result': False, 'msg': value}


class IPtableUbuntu(AbstractFirewall):
    def __init__(self, *args, **kwargs):
        # Initialize Facebook OAuth
        print('IPtablesUbuntu init')
        self.rule = iptc.Rule()
        self.obj_err = AVAFirewallErrorHandling()
        self.err_code = ReadJson("error_code.json")

    def share(self, *args, **kwargs):
        # Share on Facebook
        print('IPtablesUbuntu share')

    @staticmethod
    def get_table_name(table_name):
        # TODO: error handling
        if table_name == 'FILTER':
            table = iptc.Table.FILTER
        elif table_name == 'NAT':
            table = iptc.Table.NAT
        elif table_name == 'MANGLE':
            table = iptc.Table.MANGLE
        elif table_name == 'RAW':
            table = iptc.Table.RAW
        elif table_name == 'SECURITY':
            table = iptc.Table.SECURITY

        return iptc.Table(table)

    @staticmethod
    def get_all_tables():
        tables = ['FILTER', 'MANGLE', 'RAW']
        obj_json = ReadJson()
        ip_version = obj_json.get_ip_version()
        element = 'NAT' if ip_version == 'IPV4' else 'SECURITY'
        tables.append(element)
        return tables

    @staticmethod
    def get_match_list(matches):
        match_list = []
        for m in matches:
            match_item = {}
            match_item['name'] = m._name
            match_item['values'] = []
            all_param = m.get_all_parameters()
            param_list = []
            for key, value in all_param.iteritems():
                param_dict = {}
                param_dict['key'] = key
                param_dict['val'] = value
                param_list.append(param_dict)
            match_item['values'] = param_list
            match_list.append(match_item)
        return match_list

    def set_chain(self, table_name, goto):
        # TODO: table-name and chain
        table = self.get_table_name(table_name)
        self.chain = iptc.Chain(table, goto)

    def set_rule(self, **kwargs):
        # -ipv4
        # -ipv6
        # --protocol
        # -source address[ / mask][, ...]
        # --destination address[ / mask][, ...]
        # -m, --match commetnt dic
        # -j, --jump target
        # -g, --goto chain
        # -i, --in-interface
        # -o, --out-interface name
        # -f, --fragment
        # -c, --set-counters packets bytes
        # if 'ipv4' in kwargs:
        #     i = 0
        # if 'ipv6' in kwargs:
        #     i =0
        if 'protocol' in kwargs:
            self.rule.protocol = kwargs['protocol']

        if 'source' in kwargs:
            self.rule.src = kwargs['source']

        if 'in_interface' in kwargs:
            self.rule.in_interface = kwargs['in_interface']

        if 'out_interface' in kwargs:
            self.rule.out_interface = kwargs['out_interface']

        if 'jump' in kwargs:
            # =======TODO:error handling (completely depends on target name

            chain_name = kwargs['jump']['name']
            self.target = iptc.Target(self.rule, chain_name)

            if chain_name == 'MARK':
                self.target.set_mark = kwargs['jump']['mark']

            if chain_name == 'MASQUERADE':
                self.target.to_ports = kwargs['jump']['to_ports']

            self.rule.target = self.target

        try:
            if 'match' in kwargs:
                for match_item in kwargs['match']:
                    match = iptc.Match(self.rule, match_item['name'])
                    for item in match_item['values']:
                        match.__setattr__(item['key'], item['val'])
                    self.rule.add_match(match)
        except AVAFirewallException as e:
            AVAFirewallException(e)

    def insert_rule(self, **kwargs):
        try:
            check = self.obj_err.public_iptable_error_handling(**kwargs)
            if check['result']:
                self.set_chain(kwargs['table_name'], kwargs['goto'])
                self.set_rule(**kwargs)
                position = kwargs['position'] if 'position'in kwargs else 0
                self.chain.insert_rule(self.rule, position)
                result = True
                msg = self.err_code.get_err("200")
            else:
                result = False
                msg = check['msg']
        except Exception as e:
            print 'eeeeeeeeeeeeeeeeeeeeee'
            print e
            AVAFirewallException(e)
            msg = self.err_code.get_err("500")
            result = False

        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def append_rule(self, **kwargs):
        try:
            check = self.obj_err.public_iptable_error_handling(**kwargs)
            if check['result']:
                self.set_chain(kwargs['table_name'], kwargs['goto'])
                self.set_rule(**kwargs)
                self.chain.append_rule(self.rule)
                result = True
                msg = self.err_code.get_err("200")
            else:
                result = False
                msg = check['msg']

        except Exception as e:
            AVAFirewallException(e)
            msg = self.err_code.get_err("500")
            result = False

        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def delete_rule(self, **kwargs):
        try:
            check = self.obj_err.public_iptable_error_handling(**kwargs)
            if check['result']:
                self.set_chain(kwargs['table_name'], kwargs['goto'])
                self.set_rule(**kwargs)
                self.chain.delete_rule(self.rule)
                result = True
                msg = self.err_code.get_err("200")
            else:
                result = False
                msg = check['msg']
        except Exception as e:
            AVAFirewallException(e)
            msg = self.err_code.get_err("500")
            result = False

        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def replace_rule(self, **kwargs):
        try:
            check = self.obj_err.public_iptable_error_handling(**kwargs)
            if check['result']:
                self.set_chain(kwargs['table_name'], kwargs['goto'])
                self.set_rule(**kwargs)
                self.chain.replace_rule(self.rule, kwargs['position'])
                result = True
                msg = self.err_code.get_err("200")
            else:
                result = False
                msg = check['msg']
        except Exception as e:
            AVAFirewallException(e)
            msg = self.err_code.get_err("500")
            result = False

        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def view_all(self, table_name):
        try:
            if table_name == '':
                obj_json = ReadJson()
                table_name = obj_json.default_table()

            table = self.get_table_name(table_name)
            chain_list = []
            for chain in table.chains:
                print "Chain ", chain.name
                chain_dict = {}
                chain_dict['name'] = chain.name
                chain_obj = iptc.Chain(table, chain.name)
                chain_dict['rules'] = []
                chain_dict['jump'] = {}
                for i, rule in enumerate(chain_obj.rules):
                    rule_dict = {}
                    rule_dict = {'rule_num': i, 'src': rule.src,
                                 'dst': rule.dst, 'protocol': rule.protocol,
                                 'in': rule.in_interface,
                                 "out": rule.out_interface}
                    # '================match ================'
                    rule_dict['match'] = self.get_match_list(rule.matches)
                    chain_dict['rules'].append(rule_dict)
                    # '================target ==============='
                    chain_dict['jump']['name'] = rule.target.name
                    target = rule.target.get_all_parameters()
                    for key, value in target.iteritems():
                        chain_dict['jump'][key] = value
                chain_list.append(chain_dict)
                result = True
                msg = self.err_code.get_err("200")
        except Exception as e:
            AVAFirewallException(e)
            msg = self.err_code.get_err("500")
            result = False

        logger.log(msg['msg'])
        return {'result': result, 'msg': msg, 'data': chain_list}

    def create_chain(self, table_name, chain_name):
        table = self.get_table_name(table_name)
        try:
            table.create_chain(chain_name)
            msg = self.err_code.get_err("200")
            result = True
        except Exception as e:
            AVAFirewallException(e)
            msg = self.err_code.get_err("500")
            result = False

        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def delete_chain(self, table_name, chain_name):
        table = self.get_table_name(table_name)
        try:
            table.delete_chain(chain_name)
            msg = self.err_code.get_err("200")
            result = True
        except Exception as e:
            AVAFirewallException(e)
            msg = self.err_code.get_err("500")
            result = False

        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def rename_chain(self, table_name, old_chain, new_chain):
        table = self.get_table_name(table_name)
        try:
            table.rename_chain(old_chain, new_chain)
            msg = self.err_code.get_err("200")
            result = True
        except Exception as e:
            AVAFirewallException(e)
            msg = self.err_code.get_err("500")
            result = False

        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def view_one(self, *args, **kwargs):
        # handle it by view all
        pass

    def permanent(self, *args, **kwargs):
        pass

    def get_line_number(self, *args, **kwargs):
        # not support may be we can handle it by chain and rule
        pass
