import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="secureaws",
    version="19.12.05",
    author="Vimal Paliwal",
    author_email="hello@vimalpaliwal.com",
    description="An application to scan if basic security services are enabled on your AWS account and help you setup the same.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/paliwalvimal/secure-aws",
    license='MIT',
    keywords='aws secure security cloudtrail config encryption',
    packages=setuptools.find_packages(),
    install_requires=[
        'click',
        'Pillow',
        'pycryptodomex',
        'boto3'
    ],
    entry_points ={
        'console_scripts': [
            'secureaws = secureaws.secureaws:main'
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)