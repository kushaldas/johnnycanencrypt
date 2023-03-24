from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="johnnycanencrypt",
    version="0.13.1",
    rust_extensions=[
        RustExtension("johnnycanencrypt.johnnycanencrypt", binding=Binding.PyO3)
    ],
    package_data={"johnnycanencrypt": ["py.typed", "johnnycanencrypt.pyi"]},
    packages=["johnnycanencrypt"],
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
)
