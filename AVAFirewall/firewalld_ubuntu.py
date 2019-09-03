from firewall_abstract import AbstractFirewall


class FirewalldUbuntu(AbstractFirewall):
    def __init__(self, *args, **kwargs):
        # Initialize Twitter OAuth
        print ('twiter_init')

    def share(self, *args, **kwargs):
        print ('twitter share')
