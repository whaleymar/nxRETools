#include <iostream>
#include <cstdlib>
#include <cxxabi.h>

int main(int argc, char** argv) {

	if (argc != 2) {
		std::cout << "expected one arg" << std::endl;
		return 0;
	}

	int status;
	char* realName = abi::__cxa_demangle(argv[1], NULL, NULL, &status);
	if (status != 0) {
		std::cout << "failed with status " << status << std::endl;
	} else {
		std::cout << realName << std::endl;
	}
	std::free(realName);
}
