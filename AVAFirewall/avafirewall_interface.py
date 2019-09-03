from factory import *


class AVAFirewallInterface(object):

    def __init__(self):
        self.obj = FirewallFactory.get_share_obj()
        print self.obj

    def share(self, *args, **kwargs):
        pass

    def insert_rule(self, **kwargs):
        result = self.obj.insert_rule(**kwargs)
        return result

    def append_rule(self, **kwargs):
        result = self.obj.append_rule(**kwargs)
        return result

    def replace_rule(self, **kwargs):
        result = self.obj.replace_rule(**kwargs)
        return result

    def delete_rule(self, **kwargs):
        result = self.obj.delete_rule(**kwargs)
        return result

    def view_all(self, table_name=''):
        result = self.obj.view_all(table_name)
        return result

    def view_one(self, *args, **kwargs):
        pass

    def permanent(self, *args, **kwargs):
        pass

    def get_line_number(self, *args, **kwargs):
        pass

    def create_chain(self, table_name, chain_name):
        result = self.obj.create_chain(table_name, chain_name)
        return result

    def delete_chain(self, table_name, chain_name):
        result = self.obj.delete_chain(table_name, chain_name)
        return result

    def rename_chain(self, table_name, old_chain, new_chain):
        result = self.obj.rename_chain(table_name, old_chain, new_chain)
        return result

if __name__ == '__main__':
    print 'mmmmmmmmmmmmmmmmmmmmmmmmm'
    args = ['sss']
    kwargs = {'test': 'test_value'}
    obj = AVAFirewallInterface()
    # obj.share(*args, **kwargs)
    # ====== create_chain =============
    # result = obj.create_chain('FILTER', 'chain1')
    # print result
    # ====== rename_chain =============
    # obj.rename_chain('FILTER', 'chain1', 'chain2')
    # ====== delete_chain =============
    # obj.delete_chain('FILTER', 'chain2')
    # ============insert rule 6=======multi-port ======ok

    kwargs = {'table_name': 'FILTER', 'goto': 'chain2',
              'protocol': 'tcp'}
    kwargs['jump'] = {'name': 'ACCEPT',
                      'chain': 'ACCEPT'}
    kwargs['match'] = [{'name': 'multiport',
                        'values': [{'key': 'dports',
                                    'val': '164,165'}

                                   ]
                        },
                       {'name': 'comment',
                        'values': [{'key': 'comment',
                                    'val': 'SSH From Saba'}

                                   ]
                        }
                       ]

    result = obj.insert_rule(**kwargs)
