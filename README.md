# AVAFirewall

This module deals to manage firewall system. It includes iptables,firewalld and flask (FreeBSD). Currently handle IPtables and this library is able to develop for other firwalls like firwalld and flask.

## installation

```sh
cd AVAFirewall
pip install -r requirements.txt
pip install .
```


## How to use

You can install this module and import to your module and use.Here is a sample of using avafirewall.

```sh
from AVAFirewall.avafirewall_interface import AVAFirewallInterface
obj = AVAFirewallInterface()
obj.create_chain(table_name, chain_name)

```
## How run unit test

in the main directort run this command:

```sh
python -m unittest Tests.unit_test
```

## Description about methods
AVAFirewall includes some method that describe bellow.

#### create_chain:
This method create chain
input argument : table_name , chain_name
output:
```sh
{'result': True, 'msg': msg}
```

sample code:

```sh
obj = AVAFirewallInterface()
obj.create_chain(table_name, chain_name)
```

#### rename_chain:
This method rename chain

input argument : table_name , old_chain, new_chain

output:
```sh
{'result': True, 'msg': msg}
```

sample code:

```sh
obj = AVAFirewallInterface()
obj.rename_chain(table_name, chain_name, chain_rename)
```


#### delete_chain:
This method delete chain

input argument : table_name , chain_name

output:
```sh
{'result': True, 'msg': msg}
```

sample code:

```sh
obj = AVAFirewallInterface()
obj.delete_chain(table_name, chain_rename)
```


#### insert_rule:

Insert rule . It can insert in a specific position (rule number)(defualt position is 0)

**input argument :** Behow is a sample input for insert rule.

**goto (chain_name) is mandatory.**

For more information see document.

```sh
kwargs = {'table_name': 'FILTER', 'goto': 'chain2',
              'protocol':'tcp','position':3}
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

```


output:
```sh
{'result': True, 'msg': msg}
```

sample code:

```sh
kwargs = {'table_name': 'FILTER', 'goto': 'chain2',
              'protocol':'tcp','position':3}
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

result = obj_firewall.insert_rule(**kwargs)
```


#### append_rule:

Append rule at the end of the chain rules.


For more information see document.

input argument :

**goto (chain_name) is mandatory.**


```sh
kwargs = {'table_name': 'FILTER', 'goto': 'chain2',
              'protocol':'tcp'}
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

```


output:
```sh
{'result': True, 'msg': msg}
```

sample code:

```sh
kwargs = {'table_name': 'FILTER', 'goto': 'chain2',
              'protocol':'tcp'}
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

result = obj.append_rule(**kwargs)
```

#### replace_rule:
Replace rule instead of a position (rule number).



For more information see document.

input argument :

**goto (chain_name) is mandatory.**

```sh
kwargs = {'table_name': 'FILTER', 'goto': 'chain2',
              'protocol':'tcp'}
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

```


output:
```sh
{'result': True, 'msg': msg}
```

sample code:

```sh
kwargs = {'table_name': 'FILTER', 'goto': 'testchain','source':'5.2.2.2',
           'protocol':'udp', 'position':0}
kwargs['jump'] = {'chain': 'ACCEPT'}
kwargs['match'] = [{'name': 'comment',
                    'values': [{'key': 'comment',
                     'val': 'this is a test comment'}]
                    }
                     ]
obj.replace_rule(**kwargs)
```
#### delete_rule:
Delete rule with specific param that is indicated in input

input argument :

```sh
kwargs = {'table_name': 'FILTER', 'goto': 'testchain','source':'5.6.2.2',
          'protocol':'udp'}
kwargs['jump'] = {'chain': 'ACCEPT'}
kwargs['match'] = [{'name': 'comment',
                    'values': [{'key': 'comment',
                    'val': 'this is a test comment'}]
                    }
```
output:
```sh
{'result': True, 'msg': msg}
```

sample code:

```sh
kwargs = {'table_name': 'FILTER', 'goto': 'testchain','source':'5.6.2.2',
          'protocol':'udp'}
kwargs['jump'] = {'chain': 'ACCEPT'}
kwargs['match'] = [{'name': 'comment',
                    'values': [{'key': 'comment',
                    'val': 'this is a test comment'}]
                    }
                    ]
obj.delete_rule(**kwargs)
```

#### view_all:
By this method view all chains and rules in a specific table (default table is **FILTER**)

input argument : table_name (default is **FILTER**)

output:
```sh
{'result': True, 'msg': msg}
```

sample code:

```sh
obj.view_all(table_name)
```


#### TIPS

1. Table name in IPVS4 are :
 * FILTER,
 * NAT,
 * MANGLE and
 * RAW.

 For IPv6 the tables are:

 * FILTER,
 * MANGLE,
 * RAW and
 * SECURITY.

