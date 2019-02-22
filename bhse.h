#ifndef BHSE_H
#define BHSE_H

#include <windows.h>
#include <ctime>
#include <map>  
#include <iostream> 
#include <cstdio>  
#include <cstring>  
#include <string> 

#define MR_PAIRING_SSP 
#define Security 128
#include "pairing_1.h"

#include "miracl.h"
#include "mirdef.h"


#include "aes.h"


#define HASHLEN 32
#define INDEXSIZE 20000

/*
Name: the state map structure
*/
typedef struct _state_map{
	string st;
	int counter;
}state_map;

/*
Name: the dataset
*/
typedef struct _db{
	string index[INDEXSIZE];
	int length;
}db;

/*
Name: the handle of elliptic curve
*/
extern PFC pfc;

/*
Name: keyGen
Description: generating a public/secret key for the data user
Input: a generator P
Output: the key pair
*/
void BHSE_KeyGen(G1& g1PK, Big &sk, G1 g1P);

/*
Name: update
Description: generating the encrypted dataset
Input: a generator P, the public key  pk, the dataset (W, Index), the length wlen;
Output: the public version information g1EV, the encrypted dataset cipher.
*/
void BHSE_Updata(G1& g1EV, map<string, string> *cipher,  G1 g1P, G1 g1PK,
				 map<string, state_map> *mapSigma, string *W, db *DB, int wLen);

/*
Name: trapdoor
Description: generating a trapdoor of keyword w
Input: the secret key sk, the public version information g1EV, a keyword w
Output: the trapdoor gtT.
*/
void BHSE_Trapdoor(GT& gtT, Big sk, G1 g1EV, string w);

/*
Name:Search
Description: searching the indexes corresponding to the kewword w.
Input: the trapdoor of keyword w, the encrypted dataset cipher
Output: the encrypted index set
*/
void BHSE_Search(map<int, string> *MEI, GT gtT, map<string, string> cipher);

/*
Name: decription
Description: the decription of data user.
Input: the secret key of data user sk, the version infomation of encrypted g1EV, a keyword w, the encrypted index set
Output: the index 
*/
void BHSE_Decrypt(string index, Big sk, G1 g1EV, string w, string MEI);

void h_1(char* hash, char *str);
void h_2(char* hash, char *str);
void h_3(char* hash, char *str, int counter);
void h_4(char* hash, char *str, int counter);

void sha_kdf(char* src, int srclen, char* dst, int dstLen);

void strTochar(char* dst, int length, string src);
string charTostr(char* cstr, int length);

void copyst(state_map* dst, state_map src);
int charToint(char* pbSrc, int iOffset);
void intTochar(char* pbDes, int iSource);

void getRandom(char* strRandom, int length);
void charHexPrint(char* pbSrc, int length);
void stringHexPrint(string input, int length);

#endif
