#include "bhse.h"
#include "aes.h"

PFC pfc(Security);

//h1(s)
void h_1(char* hash, char *str)
{
	int i; 
	sha256 sh;
	char ha[HASHLEN] = {0};
	shs256_init(&sh);
	shs256_process(&sh, 1);
	for (i=0; i < 16;i++)
	{
		shs256_process(&sh,str[i]);
	}
	shs256_hash(&sh,ha);
	memcpy(hash, ha, HASHLEN);
}
//36bytes
void h_2(char* hash, char *str)
{
	int i; 
	sha256 sh;
	char ha[HASHLEN] = {0};
	shs256_init(&sh);
	shs256_process(&sh, 0);
	for (i=0;i < 16;i++)
	{
		shs256_process(&sh,str[i]);
	}
	shs256_hash(&sh,ha);
	memcpy(hash, ha, HASHLEN);
}
void h_3(char* hash, char *str, int counter)
{
	int i; 
	sha256 sh;
	char ha[HASHLEN] = {0};
	char bc[4] = { 0 };
	shs256_init(&sh);
	for (i=0;i < 16;i++)
	{
		shs256_process(&sh,str[i]);
	}
	intTochar(bc, counter);
	for (i = 0; i < 4; i++)
	{
		shs256_process(&sh, bc[i]);
	}
	shs256_hash(&sh,ha);
	memcpy(hash, ha, HASHLEN);
}
void h_4(char* hash, char *str, int counter)
{
	int i; 
	sha256 sh;
	char ha[HASHLEN] = {0};
	char bc[4] = { 0 };
	shs256_init(&sh);
	for (i=0;i < 16;i++)
	{
		shs256_process(&sh,str[i]);
	}
	shs256_process(&sh,1);
	intTochar(bc, counter);
	for ( i = 0; i < 4; i++)
	{
		shs256_process(&sh, bc[i]);
	}
	shs256_hash(&sh,ha);
	sha_kdf(ha, HASHLEN, hash,  36);
}

void sha_kdf(char* src, int srclen, char* dst, int dstLen)
{
	int i, j, t;
	int bitklen;
	sha256 sh;
	int hashlen = 256;
	char Ha[HASHLEN];
	char ct[4] = { 0,0,0,1 };
	bitklen = dstLen * 8;
	//设置输出块数/
	if (bitklen%hashlen)
		t = bitklen / hashlen + 1;
	else
		t = bitklen / hashlen;
	//s4: K=Ha1||Ha2||...
	for (i = 1; i<t; i++)
	{
		//s2: Hai=Hv(Z||ct)
		shs256_init(&sh);
		for (j=0;j < srclen;j++)
		{
			shs256_process(&sh,src[j]);
		}
		for (j =0; j < 4; j++)
		{
			shs256_process(&sh,ct[j]);
		}
		shs256_hash(&sh,Ha);
		
		memcpy((dst + (hashlen / 8)*(i - 1)), Ha, hashlen / 8);
		if (ct[3] == 0xff)
		{
			ct[3] = 0;
			if (ct[2] == 0xff)
			{
				ct[2] = 0;
				if (ct[1] == 0xff)
				{
					ct[1] = 0;
					ct[0]++;
				}
				else ct[1]++;
			}
			else ct[2]++;
		}
		else ct[3]++;
	}
	//s3: klen/v 非整数的处理
	shs256_init(&sh);
	for (j=0;j<srclen;j++)
	{
		shs256_process(&sh,src[j]);
	}
	for (j =0; j < 4; j++)
	{
		shs256_process(&sh,ct[j]);
	}
	shs256_hash(&sh,Ha);

	if (bitklen%hashlen)
	{
		i = (hashlen - bitklen + hashlen * (bitklen / hashlen)) / 8;
		j = (bitklen - hashlen * (bitklen / hashlen)) / 8;
		memcpy((dst + (hashlen / 8)*(t - 1)), Ha, j);
	}
	else
	{
		memcpy((dst + (hashlen / 8)*(t - 1)), Ha, hashlen / 8);
	}
}
void strTochar(char* dst, int length, string src)
{
	char *p = (char*)src.data();
	memcpy(dst, p, length);
	p = NULL;
}
string charTostr(char* cstr, int length)
{
	int i = 0;
	string result;
	result.assign(cstr, length);
	return result;
}
void getRandom(char* strRandom, int length)
{
	int i = 0;
	for (i = 0; i <length; i++)
	{
		strRandom[i] = (char)rand();
	}
}
void copyst(state_map * dst, state_map src)
{
	dst->counter = src.counter;
	dst->st = src.st;
}
int charToint(char* pbSrc, int iOffset)
{
	int iValue;   
	///////////////////
	iValue = ((((unsigned int)pbSrc[iOffset] << 24) & 0xff000000)
		| (((unsigned int)pbSrc[iOffset+1] << 16) & 0x00ff0000)
		| (((unsigned int)pbSrc[iOffset+2] << 8) & 0x0000ff00)
		| (((unsigned int)pbSrc[iOffset+3]) & 0x000000ff));
	return iValue; 
}
void intTochar(char* pbDes, int iSource)
{
	pbDes[0] = (char)((unsigned int)iSource>>24);
	pbDes[1] = (char)((unsigned int)iSource>>16);
	pbDes[2] = (char)((unsigned int)iSource>>8);
	pbDes[3] = (char)((unsigned int)iSource);
}
void charHexPrint(char* pbSrc, int length)
{
	int i; 
	for (i = 0; i < length; i++)
	{
		printf("%02x", (unsigned char)pbSrc[i]);
	}
	printf("\n");
}
void stringHexPrint(string input, int length)
{
	int i;
	for (i = 0; i < length; i++)
	{
		printf("%02x", (unsigned char)input[i]);
	}
	printf("\n");
}

void BHSE_KeyGen(G1& g1PK, Big &sk, G1 g1P)
{
	pfc.random(sk);
	g1PK = pfc.mult(g1P, sk);
}

void BHSE_Updata(G1& g1EV,map<string, string> *cipher,  G1 g1P, G1 g1PK,
				 map<string, state_map> *mapSigma, string *W, db *DB, int wLen)
{
	Big br;
	G1 rpk;
	G1 g1w;
	GT gtt;
	int i, j, k;
	string tmpw;
	state_map tmpst;
	char bm[4] = {0};
	char cw[16] = {0};
	char tmp[16] = {0};
	char st_c[16] = {0};
	char st_c1[16] = {0};
	char hash12[32] = {0};
	char hashtmp[32] = {0};
	char hash4[36] = {0};
	string tmpkey;
	string tmpvalue;
	int cwLength = 0;
	int indexLength = 0;
	pfc.random(br);
	g1EV = pfc.mult(g1P, br);
	rpk = pfc.mult(g1PK, br);
	//////////////////////////////////////////////////////////////////////////
	for (i = 0; i < wLen; i++)
	{
		tmpw = W[i];
		if (mapSigma->count(tmpw) == 0)
		{
			getRandom(tmp, 16);
			tmpst.counter = 0;
			tmpst.st = charTostr(tmp, 16);
		}
		else
		{
			tmpst=(*mapSigma)[tmpw];
		}
		///get k
		strTochar(st_c, 16, tmpst.st);
		getRandom(tmp, 16);
		AES_E((unsigned char*)st_c1, (unsigned char*)st_c, (unsigned char*)tmp, 16);
		tmpst.counter = tmpst.counter + 1;
		tmpst.st = charTostr(st_c1, 16);
		(*mapSigma)[tmpw]=tmpst;
		//////
		h_1(hash12, st_c1);
		string tmpkey0 = charTostr(hash12, HASHLEN);
		h_2(hash12, st_c1);
		intTochar(bm, DB[i].length);
		hash12[0] = hash12[0]^bm[0];
		hash12[1] = hash12[1]^bm[1];
		hash12[2] = hash12[2]^bm[2];
		hash12[3] = hash12[3]^bm[3];
		//(m||k)
		for (j = 4; j < 20; j++)
		{
			hash12[j] = hash12[j]^tmp[j-4];
		}
		string tmpvalue0 = charTostr(hash12, HASHLEN);
		cipher->insert(map<string, string>::value_type (tmpkey0, tmpvalue0));
		////////////////
		for (j = 0; j < DB[i].length; j++)
		{
			//EI
			//cout << "ency_index_"<<j<< endl;
			strTochar(cw, 16, W[i]);
			pfc.start_hash();
			pfc.add_to_hash(rpk);
			pfc.add_to_hash(cw, 16, j);
			pfc.finish_hash_to_char1(hashtmp);
			strTochar(tmp, 16, DB[i].index[j]);
			for (k = 16; k < HASHLEN; k++)
			{
				hashtmp[k] = hashtmp[k] ^ tmp[k-16];
			}
			//cipher
			h_3(hash12, st_c1, j);
			string tmpkey1 = charTostr(hash12, HASHLEN);

			h_4(hash4, st_c1, j);
			intTochar(bm,j);
			hash4[0] = hash4[0]^bm[0];
			hash4[1] = hash4[1]^bm[1];
			hash4[2] = hash4[2]^bm[2];
			hash4[3] = hash4[3]^bm[3];
			for (k = 4; k < HASHLEN+4; k++)
			{
				hash4[k] = hash4[k] ^hashtmp[k-4];
			}
			string tmpvalue1 = charTostr(hash4, 36);
			
			cipher->insert(map<string, string>::value_type (tmpkey1, tmpvalue1));
		
		}

     	char *p = (char*)W[i].data();
		pfc.hash_and_map(g1w, p);
		gtt = pfc.pairing(g1w, rpk);
		pfc.start_hash();
		pfc.add_to_hash(gtt);
		pfc.finish_hash_to_char1(hash12);
		string tmpkey2 = charTostr(hash12, HASHLEN);
		////////////////////
		pfc.start_hash();
		pfc.add_to_hash(gtt);
		pfc.add_to_hash(0);
		pfc.finish_hash_to_char1(hash12);
		for (k = 0; k <16; k++)
		{
			hash12[k] = hash12[k] ^ st_c1[k];
		}
		string tmpvalue2 = charTostr(hash12, HASHLEN);
		cipher->insert(map<string, string>::value_type (tmpkey2, tmpvalue2));	
	}
}

void BHSE_Trapdoor(GT& gtT, Big sk, G1 g1EV, string w)
{
	G1 g1w;
	G1 g1tmp;
	char *p = (char*)w.data();
	pfc.hash_and_map(g1w, p);
	g1tmp = pfc.mult(g1w, sk);	gtT = pfc.pairing(g1tmp, g1EV);
}

void BHSE_Search(map<int, string> *MEI, GT gtT, map<string, string> cipher)
{
	char st[16] = { 0 };
	char chash[36] = { 0 };
	char hash123[32] = { 0 };
	char cm[4] = { 0 };
	char key[16] = { 0 };
	char hash4[36] = { 0 };
	char st_tmp[16] = {0};
	int m = 0;
	int j,k;
	int counter = 0;
	//1
	pfc.start_hash();
	pfc.add_to_hash(gtT);
	pfc.finish_hash_to_char1(hash123);
	string tmpkey = charTostr(hash123, HASHLEN);
	//2.
	if (cipher.count(tmpkey) == 0)
	{
		printf("search end\n");
		return;
	}
	string tmpvalue = cipher[tmpkey];
	////
	strTochar(chash, 32, tmpvalue);
	pfc.start_hash();
	pfc.add_to_hash(gtT);
	pfc.add_to_hash(0);
	pfc.finish_hash_to_char1(hash123);
	for (k = 0; k <16; k++)
	{
		st[k] = hash123[k] ^ chash[k];
	}
	while (1)
	{
		h_1(hash123, st);
		string tmpkey1 = charTostr(hash123, HASHLEN);
		if (cipher.count(tmpkey1) == 0)
		{
			cout << counter << endl;
			printf("search over \n");
			return;
		}
		string tmpvalue1 = cipher[tmpkey1];
		strTochar(chash, 32, tmpvalue1);
		h_2(hash123, st);
		//(m||)
		cm[0] = hash123[0]^chash[0];
		cm[1] = hash123[1]^chash[1];
		cm[2] = hash123[2]^chash[2];
		cm[3] = hash123[3]^chash[3];
		m = charToint(cm, 0);
		//k
		for (j = 0; j < 16; j++)
		{
			key[j] = hash123[j+4]^chash[j+4];
		}
		for (j = 0; j < m; j++)
		{	
			//cipher
			h_3(hash123, st, j);
			string tmpkey2 = charTostr(hash123, HASHLEN);
			string tmpvalue2 = cipher[tmpkey2];
			strTochar(chash, 36, tmpvalue2);
			h_4(hash4, st, j);
			for (k = 0; k < HASHLEN+4; k++)
			{
				hash4[k] = hash4[k] ^chash[k];
			}
			string tmpvalue3 = charTostr(hash4, 36);
			//MEI->insert(map<int, string>::value_type (counter, tmpvalue3));
			counter++;
		}
		AES_D((unsigned char*)st_tmp, (unsigned char*)st, (unsigned char*)key, 16);
		memcpy(st, st_tmp, 16);
	}

}

void BHSE_Decrypt(string index, Big sk, G1 g1EV, string w, string MEI)
{
	G1 g1Tmp;
	char cresult[32] = { 0 };
	char cMEI[36] = { 0 };
	char cJ[4] = { 0 };
	char cw[16] = { 0 };
	int counter = 0;
	strTochar(cMEI, 36, MEI);
	strTochar(cw, 16, w);
	memcpy(cJ, cMEI, 4);
	counter = charToint(cw, 0);
	g1Tmp = pfc.mult(g1EV, sk);
	pfc.start_hash();
	pfc.add_to_hash(g1Tmp);
	pfc.add_to_hash(cw, 16, counter);
	pfc.finish_hash_to_char1(cresult);
}

