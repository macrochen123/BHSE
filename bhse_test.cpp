
#include "bhse_test.h"
#define DBSIZE 1
void bhse_test()
{
	LARGE_INTEGER freq;
	LARGE_INTEGER start_t, stop_t;
	double exe_time = 0;
	int counter = 10;
	Big sk;
	G1 g1PK, g1EV, P;
	GT gtT;
	map<string, string> cipher;
	map<string, state_map> mapSigma;
	map<int, string> MEI;
	string W[DBSIZE];
	db DB[DBSIZE];
	char tmp[16] = {0};
	char aCipher[16] = { 0 };
	char *key = "B95AC127221FAC93641A8BA170DB2210";
	char *aM= "B95AC127221FAC93641A8BA170DB2210";
	string strtmp;
	int i = 0;
	int j = 0;
	QueryPerformanceFrequency(&freq);
	for (i = 0; i < DBSIZE; i++)
	{
		getRandom(tmp, 16);
		strtmp = charTostr(tmp, 16);
		W[i] = strtmp;
		DB[i].length =10000;
		for ( j = 0; j < DB[i].length; j++)
		{
			getRandom(tmp, 16);
			strtmp = charTostr(tmp, 16);
			DB[i].index[j] = strtmp;
		}
	}
	pfc.random(P);
	exe_time = 0;
	for (i = 0; i < 1000; i++)
	{
		QueryPerformanceCounter(&start_t);
		AES_E((unsigned char*)aCipher, (unsigned char*)aM, (unsigned char*)key, 16);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of AES_E= " << exe_time / 1000 << " ms" << endl;

	exe_time = 0;
	Big l;
	G1 g1R;
	pfc.random(l);
	for (i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t);
		g1R = pfc.mult(P, l);//stand
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of stand_mult= " << exe_time / counter << " ms" << endl;

	exe_time = 0;
	for (i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t);
		pfc.hash_to_Char("B95AC127221FAC93641A8BA170DB2211");
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of general hash= " << exe_time / counter << " ms" << endl;

	exe_time = 0;
	for (i = 0; i < counter; i++)
	{
		G1 p;
		QueryPerformanceCounter(&start_t);
		pfc.hash_and_map(p, tmp);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of HTP= " << exe_time / counter << " ms" << endl;

	exe_time = 0;
	G1 a, b;
	pfc.random(a);
	pfc.random(b);
	for (i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t);
		pfc.pairing(a, b);//e
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of e= " << exe_time / counter << " ms" << endl;

	exe_time = 0;
	for (i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t);
		BHSE_KeyGen(g1PK, sk, P);///
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of KeyGen = " << exe_time / counter << " ms" << endl;

	exe_time = 0;
	for (i = 0; i < 10; i++)
	{
		QueryPerformanceCounter(&start_t);
		BHSE_Updata(g1EV, &cipher, P, g1PK, &mapSigma, W, DB, DBSIZE);///
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Encryption = " << exe_time/10 << " ms" << endl;
	exe_time = 0;
	for (i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t);
		BHSE_Trapdoor(gtT, sk, g1EV, W[0]);///
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Trapdoor = " << exe_time / counter << " ms" << endl;

	exe_time = 0;
	for (i = 0; i < 1; i++)
	{
		QueryPerformanceCounter(&start_t);
		BHSE_Search(&MEI, gtT, cipher);///
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Search = " << exe_time/1 << " ms" << endl;

	exe_time = 0;
	string index;
	string strMEI = MEI[1];
	for (i = 0; i < 1000; i++)
	{
		QueryPerformanceCounter(&start_t);
		BHSE_Decrypt(index, sk, g1EV, W[0], strMEI);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Decrypt = " << exe_time/1000 << " ms" << endl;
}