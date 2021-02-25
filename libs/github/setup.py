import setuptools

setuptools.setup(
    name='github',
    description='Lightweight (unpublished) python library for the purpose of this project.',
    version='0.0.1',
    packages=setuptools.find_packages(),
    install_requires=['pynacl', 'requests'],
    entry_points={
        'console_scripts': [
            'github=github:main'
        ]
    }
)
