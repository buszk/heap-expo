CC=clang-10
ROOT=`readlink -f ..`
CFLAGS=-Xclang -load -Xclang $(ROOT)/llvm-plugins/libplugins-opt.so -g
CFLAGSDS=-Xclang -load -Xclang $(ROOT)/llvm-plugins/libplugins-dangsan.so -g
LDFLAGS=-ldl -lstdc++ -lm -lunwind -pthread\
		$(ROOT)/gperftools-metalloc/.libs/libtcmalloc.a \
		$(ROOT)/metapagetable/obj/.libs/libmetapagetable.a \
		$(ROOT)/staticlib/obj/libmetadata.a
		

TESTS=  arg_ref_uaf \
		arg_uaf \
		dangling \
		global_uaf \
		heap_struct \
	    heap_uaf \
		loop \
		realloc_uar \
		scope \
		stack_const_uaf \
		stack_func_uaf \
		stack_struct \
		stack_struct_copy_uaf \
		stack_struct_uaf \
		stack_uaf \
		volatile_uaf

%: %.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

%_O2: %.c
	$(CC) $(CFLAGS) -O2 $< -o $@ $(LDFLAGS)

%_ds: %.c
	$(CC) $(CFLAGSDS) -O2 $< -o $@ $(LDFLAGS)


%.ll: %.c
	$(CC) $(CFLAGSDS) -O2 -S -emit-llvm $< -o $@

test: $(TESTS) $(TESTS:=_O2) $(TESTS:=_ds)
	./run_test.sh arg_ref_uaf 139
	./run_test.sh arg_ref_uaf_O2 139
	./run_test.sh arg_ref_uaf_ds 139

	./run_test.sh arg_uaf 139
	./run_test.sh arg_uaf_O2 139
	./run_test.sh arg_uaf_ds 139

	./run_test.sh dangling 0
	./run_test.sh dangling_O2 0
	./run_test.sh dangling_ds 0

	./run_test.sh global_uaf 139
	./run_test.sh global_uaf_O2 139
	./run_test.sh global_uaf_ds 139

	# Depends on if copy constructor is optimized to a pointer store
	./run_test.sh heap_struct 0
	./run_test.sh heap_struct_O2 139
	# DangSan is not able to detect UAF
	./run_test.sh heap_struct_ds 0

	./run_test.sh heap_uaf 139
	./run_test.sh heap_uaf_O2 139
	./run_test.sh heap_uaf_ds 139

	./run_test.sh loop 0
	./run_test.sh loop_O2 0
	./run_test.sh loop_ds 0

	./run_test.sh realloc_uar 139
	./run_test.sh realloc_uar_O2 139
	# DangSan is not able to detect UAF
	./run_test.sh realloc_uar_ds 0

	./run_test.sh scope 0
	./run_test.sh scope_O2 0
	./run_test.sh scope_ds 0

	./run_test.sh stack_const_uaf 139
	./run_test.sh stack_const_uaf_O2 139
	# DangSan is not able to detect UAF
	./run_test.sh stack_const_uaf_ds 0

	./run_test.sh stack_func_uaf 139
	./run_test.sh stack_func_uaf_O2 139
	# DangSan is not able to detect UAF
	./run_test.sh stack_func_uaf_ds 0

	# Depends on if copy constructor is optimized to a pointer store
	./run_test.sh stack_struct_copy_uaf 0
	./run_test.sh stack_struct_copy_uaf_O2 139
	# DangSan is not able to detect UAF
	./run_test.sh stack_struct_copy_uaf_ds 0

	./run_test.sh stack_struct_uaf 139
	./run_test.sh stack_struct_uaf_O2 139
	# DangSan is not able to detect UAF
	./run_test.sh stack_struct_uaf_ds 0

	./run_test.sh stack_uaf 139
	./run_test.sh stack_uaf_O2 139
	# DangSan is not able to detect UAF
	./run_test.sh stack_uaf_ds 0

	./run_test.sh volatile_uaf 139
	./run_test.sh volatile_uaf_O2 139
	# DangSan is not able to detect UAF
	./run_test.sh volatile_uaf_ds 139
	

ll: $(addsuffix .ll,$(TESTS))

clean: 
	rm -rf $(TESTS) $(addsuffix .ll,$(TESTS)) $(addsuffix _O2,$(TESTS)) $(TESTS:=_ds) *.txt
