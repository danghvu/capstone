from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

VERSION = '2.0'

flags = ['-O3', '-fomit-frame-pointer']

ext_modules = [ Extension("capstone.capstone", ["capstone/capstone.py"], extra_compile_args=flags),
    Extension("capstone.ccapstone", language='clang', sources=["capstone/ccapstone.pyx"], libraries=["capstone"], extra_compile_args=flags),
    Extension("capstone.arm", ["capstone/arm.py"]),
    Extension("capstone.arm_const", ["capstone/arm_const.py"]),
    Extension("capstone.arm64", ["capstone/arm64.py"]),
    Extension("capstone.arm64_const", ["capstone/arm64_const.py"]),
    Extension("capstone.mips", ["capstone/mips.py"]),
    Extension("capstone.mips_const", ["capstone/mips_const.py"]),
    Extension("capstone.ppc", ["capstone/ppc.py"]),
    Extension("capstone.ppc_const", ["capstone/ppc_const.py"]),
    Extension("capstone.x86", ["capstone/x86.py"]),
    Extension("capstone.x86_const", ["capstone/x86_const.py"])
]

setup(
    provides     = ['capstone'],
    name         = 'capstone',
    package_data = {'capstone': ['__init__.py']},
    version      = VERSION,
    cmdclass = {'build_ext': build_ext},
    ext_modules = ext_modules,
    author       = 'Nguyen Anh Quynh',
    author_email = 'aquynh@gmail.com',
    description  = 'Capstone disassembly engine',
    url          = 'http://www.capstone-engine.org',
    classifiers  = [
                'License :: OSI Approved :: BSD License',
                'Programming Language :: Python :: 2',
                ],
)
