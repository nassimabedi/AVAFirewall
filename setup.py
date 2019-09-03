from setuptools import setup, find_packages

print find_packages()

setup(name='AVAFirewall',
      version='0.1',
      description='The AVAFirewall to work with firwall commands.',
      url='',
      author='Nassim Abedi',
      author_email='nassimabedi@gmail.com',
      license='MIT',
      packages=find_packages(),
      include_package_data=True,
      package_data={
            'AVAFirewall':['*.json'],
            },
      zip_safe=False)
