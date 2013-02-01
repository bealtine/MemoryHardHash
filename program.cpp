#include <iostream>
#include <string>
#include "MemoryHardHasher.hpp"

using namespace Jvs::Security;
using namespace std;

int main(void)
{
	MemoryHardHasher hasher;

	hasher.ArraySize(128, SizeUnits::MB);
	hasher.JumpCount(500);
	cout << hasher.Hash("Hello!", [&](int progress, unsigned long location)
		{
			std::cout << "Hashing: " << std::dec << progress << "% complete (" << location << " / " << hasher.ArraySize() << ")" << std::endl;
	}) << endl;
	return 0;
}