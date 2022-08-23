from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="johnnycanencrypt",
    version="0.9.0",
    rust_extensions=[RustExtension("johnnycanencrypt.johnnycanencrypt", binding=Binding.PyO3)],
    packages=["johnnycanencrypt"],
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
)
