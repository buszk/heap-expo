# HeapExpo

## Introduction
HeapExpo is an instrumentation tool to mitigate use-after-free(UAF) vulnerability which is widely present in C/C++ programs. Previous work DangSan is unable to cover important source of danging pointers like local variables and function arguments. HeapExpo addresses the coverage gap by pinpointing promoted pointer that can casue UAF. 

## Prerequiste
Install dependencies. 

```
sudo apt-get update
sudo apt-get install -y bison build-essential gettext git pkg-config python ssh subversion wget time vim
```

For runnig comparision tests, you need to install llvm-10.
```
sudo apt-get install -y automake libtool-bin libunwind-dev
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

#### Normal setup
```
git clone https://github.com/buszk/heap-expo.git
cd heap-expo
PATHSPEC=/path/to/spec/cpu2006 ./autosetup.sh
```
#### Docker setup
We actually recomment using a docker environment to avoid mess in your system. Create a docker container with the following command. Adjust **cpu2006** directory properly.
```
docker run --name heap-expo --privileged -it -v /path/to/spec/cpu2006:/cpu2006 debian:9
```
Inside the docker container, install depencies and then run the following script to build.
```
git clone https://github.com/buszk/heap-expo.git /heap-expo
cd /heap-expo
FORCE_UNSAFE_CONFIGURE=1 PATHSPEC=/cpu2006 ./autosetup.sh
```

After build, use `./run-spec-cpu2006-{baseline-lto,heap-expo,dangsan}.sh all` to run the benchmarks. The results available in /cpu2006/result are shown in Figure 2 of our paper. 

### Benchmarking

```
./run-spec-cpu2006-dangsan.sh all
```

## Coverage Test (Compared with DangSan) 

All tested c programs are located at [tests/](https://github.com/buszk/heap-expo/tree/port/tests) in port branch. We summarized the test results to Table 5.

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
