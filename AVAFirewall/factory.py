from iptable_ubuntu import IPtableUbuntu
from firewalld_ubuntu import FirewalldUbuntu
from flask_freebsd import FlaskFreeBSD
from file_handler import ReadJson


class FirewallFactory(object):
    __share_classes = {
        "iptable_ubuntu": IPtableUbuntu,
        "firewalld_ubuntu": FirewalldUbuntu,
        "flask_freeBSD": FlaskFreeBSD
    }

    @staticmethod
    def get_share_obj():
        obj_json = ReadJson()
        file_name = obj_json.get_file_path()
        print (file_name)
        os = obj_json.get_os()
        firewall_type = obj_json.get_type_firewall()
        print(os)
        args = ['']
        kwargs = {'test': 'test_value'}
        kwargs['default_table'] = obj_json.get_default_table()
        kwargs['default_chain'] = obj_json.get_default_chain()
        name = firewall_type + '_' + os
        share_class = FirewallFactory.__share_classes.get(name.lower(), None)

        if share_class:
            return share_class(*args, **kwargs)
        raise NotImplementedError("The requested sharing " +
                                  "has not been implemented")


if __name__ == '__main__':
    args = ['sss']
    kwargs = {'test': 'test_value'}
    obj = FirewallFactory.get_share_obj("iptable_ubuntu", *args, **kwargs)
    obj.share("Something")
