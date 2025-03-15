#pragma once

//���� ������ cƯ������ �ִ��� ĸ��ȭ�� ���� �Լ����� ����, toCiper(),toPlain()
//��ȣȭ�� ���� ������ ��� ����ü, ���� �迭�� �Ҵ� �� calloc�� ���� �Ҵ� �ϴ� ���� ��õ��.
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