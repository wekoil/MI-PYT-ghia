from setuptools import setup

with open('README') as f:
    long_description = ''.join(f.readlines())

setup(
    name='ghia_michaj24',
    version='0.3',
    description='GitHub issue auto assigner',
    long_description=long_description,
    author='Jan Michal',
    author_email='michaj24@fit.cvut.cz',
    keywords='github,issue,assigner,automation',
    license='MIT',
    url='https://github.com/wekoil/MI-PYT-ghia',
    packages=['ghia'],
    package_data={'ghia': ['templates/*']},
    include_package_data=True,
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Framework :: Flask',
    	'Environment :: Console',
    	'Environment :: Web Environment',
        ],
    zip_safe=False,
    install_requires=['requests', 'click>=6', 'Flask', 'configparser'],
    entry_points={'console_scripts': ['ghia = ghia.cli:main', ], },
)