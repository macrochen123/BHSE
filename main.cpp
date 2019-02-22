
#include "bhse_test.h"
using namespace std;

void main()
{
	time_t seed;
	time(&seed);
	irand((long)seed);
	srand( (unsigned)time(NULL));
	///////////////////
	bhse_test();
	system("pause");
}