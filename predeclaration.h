#pragma once

//절차 지향인 c특성으로 최대한 캡슐화를 위한 함수들이 존재, toCiper(),toPlain()
//복호화를 위한 정보가 담긴 구조체, 만일 배열을 할당 시 calloc로 동적 할당 하는 것을 추천함.
typedef struct encryptionInfo {

	int keylen;
	int* key;
	int blankbox;
	char* filename;

}encryptionInfo;

encryptionInfo* checkArray(encryptionInfo* info, int* arrsize);

char* makeFilename(char* filename, int filecnt);
char* fileRead(char* filename);
void fileWrite(char* filename, char* text);

char* encrypt(char* plaintext, encryptionInfo* info);
char* decryption(char* cipertext, encryptionInfo* info);

int generateKeylen(int textlen);
int* generateKey(int keylen);

encryptionInfo* toCiper(encryptionInfo* info, int* filecnt, int* arrcnt);
encryptionInfo* toPlain(encryptionInfo* info, int* filecnt, int* arrcnt);

void transpositionCiper();