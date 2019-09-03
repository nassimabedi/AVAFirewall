import unittest
from AVAFirewall.avafirewall_interface import AVAFirewallInterface
from AVAFirewall.file_handler import ReadJson
import json


class TestAVAFirewallInterfaceMethods(unittest.TestCase):

    obj = AVAFirewallInterface()
    table_name = 'FILTER'
    chain_name = 'chain1'
    chain_rename = 'testchain'
    kwargs = {'table_name': 'FILTER', 'goto': 'chain2',
              'protocol': 'tcp'}
    kwargs['jump'] = {'name': 'DROP',
                      'chain': 'DROP'}
    kwargs['match'] = [{'name': 'tcp',
                        'values': [{'key': 'dport',
                                    'val': '22'}]
                        },
                       {'name': 'iprange',
                        'values': [{'key': 'src_range',
                                    'val': '192.168.1.100-192.168.1.200'},
                                   {'key': 'dst_range',
                                    'val': '172.22.33.106'}
                                   ]
                        }
                       ]

    def test_create_chain(self):
        try:
            self.obj.create_chain(self.table_name, self.chain_name)
            result = True
        except Exception as e:
            result = False

        self.assertTrue(result, True)

    def test_rename_chain(self):
        try:
            self.obj.rename_chain(self.table_name, self.chain_name,
                                  self.chain_rename)
            result = True
        except Exception as e:
            result = False

        self.assertTrue(result, True)

    def test_insert_rule(self):
        try:
            self.obj.insert_rule(self.kwargs)
            result = True
        except Exception as e:
            result = False

        self.assertTrue(result, True)

    def test_replace_rule(self):
        try:
            self.obj.replace_rule(self.kwargs)
            result = True
        except Exception as e:
            result = False

        self.assertTrue(result, True)

    def test_delete_rule(self):
        try:
            self.obj.delete_rule(self.kwargs)
            result = True
        except Exception as e:
            result = False

        self.assertTrue(result, True)

    def test_delete_chain(self):
        try:
            self.obj_firewall.delete_chain(self.table_name, self.chain_rename)
            result = True
        except Exception as e:
            result = False

        self.assertTrue(result, True)


class TestReadJsonMethods(unittest.TestCase):

    obj_file = ReadJson()

    def test_get_file_path(self):
        self.assertFalse(isinstance(self.obj_file.get_file_path(), dict))

    def test_get_os(self):
        # check input
        self.assertFalse(isinstance(self.obj_file.get_os(), dict))

    def test_get_type_firewall(self):
        self.assertFalse(isinstance(self.obj_file.get_type_firewall(), dict))

    def test_get_default_table(self):
        self.assertFalse(isinstance(self.obj_file.get_default_table(), dict))

    def test_get_default_chain(self):
        default_chain = self.obj_file.get_default_chain()
        self.assertEqual(default_chain, 'INPUT')
        self.assertFalse(isinstance(default_chain, dict))


if __name__ == '__main__':
    unittest.main()
