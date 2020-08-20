# HeapExpo

## Introduction
HeapExpo is an instrumentation tool to mitigate use-after-free(UAF) vulnerability which is widely present in C/C++ programs. Previous work DangSan is unable to cover important source of danging pointers like local variables and function arguments. HeapExpo addresses the coverage gap by pinpointing promoted pointer that can casue UAF. 

## Prerequiste
Install dependencies. 

```
sudo apt-get install bison build-essential gettext git pkg-config python ssh subversion wget time automake libtool-bin libunwind-dev
```

For runnig comparision tests, you need to install llvm-10.
```
sudo apt-get install -y libllvm-10-ocaml-dev libllvm10 llvm-10 llvm-10-dev llvm-10-doc llvm-10-runtime clang-10 clang-tools-10 libclang-common-10-dev libclang-10-dev libclang1-10 libc++-10-dev libc++abi-10-dev
```

Or install llvm-10 more easily with llvm scripts
```
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 10
```


## CPU2006 Benchmark 
### Installation

Run the following commands to setup
```
git clone https://github.com/buszk/heap-expo.git
cd heap-expo
PATHSPEC=/path/to/spec/cpu2006 ./autosetup.sh
FORCE_UNSAFE_CONFIGURE=1 PATHSPEC=/path/to/spec/cpu2006 ./autosetup.sh
```

### Benchmarking

```
./run-spec-cpu2006-dangsan.sh all
```

## Coverage Test (Compared with DangSan) 

All tested c programs are located at [tests/](https://github.com/buszk/heap-expo/tree/port/tests) in port branch. 

To provide an easy test environment, we ported HeapExpo from llvm-3.8 to llvm-10. It should also be compatible with other modern versions. We put our ported version under the port branch. In order to build our test, you can use the following commands.

```
git clone https://github.com/buszk/heap-expo.git
cd heap-expo
git checkout port
make -j
```

Run test with 
```
make test
```

The  compared coverage test script is in [Makefile](https://github.com/buszk/heap-expo/blob/port/tests/Makefile). You can find out the tests where HeapExpo detects UAF while DangSan fails.
