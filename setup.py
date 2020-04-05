import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="flask_oidc_verifier",
    version="0.0.6",
    author="Vishal Kuo",
    author_email="vishalkuo@gmail.com",
    description="Run oidc token verification",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vishalkuo/flask-oidc-verifier",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
