from firewall_abstract import AbstractFirewall


class FlaskFreeBSD(AbstractFirewall):
    def __init__(self, *args, **kwargs):
        # Initialize Twitter OAuth
        print ('FlaskFreeBSD_init')

    def share(self, *args, **kwargs):
        print ('FlaskFreeBSD share')
