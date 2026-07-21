"""
Build script for the BinBin Cython extension.

Usage
-----
    cd BinBin
    python setup.py build_ext --inplace

This is entirely optional — BinBin works in pure Python without it.
"""
from setuptools import setup, Extension

try:
    from Cython.Build import cythonize
    ext_modules = cythonize(
        [Extension("BinBin._cblock", ["_cblock.pyx"])],
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
        },
    )
except ImportError:
    # Cython not installed — skip the extension
    ext_modules = []

setup(
    name="BinBin",
    ext_modules=ext_modules,
)
