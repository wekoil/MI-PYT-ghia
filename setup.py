from setuptools import setup

with open('README.adoc') as f:
    long_description = ''.join(f.readlines())

setup(
    name='ghia_wekoil',
    version='0.3',
    description='GitHub issue auto assigner',
    long_description=long_description,
    author='Jan Michal',
    author_email='michaj24@fit.cvut.cz',
    keywords='github,issue,assigner',
    license='MIT',
    url='https://github.com/wekoil/MI-PYT-ghia',
    packages=['ghia'],
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],
    zip_safe=False,
)