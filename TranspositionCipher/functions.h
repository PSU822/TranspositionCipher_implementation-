#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include"predeclaration.h"


#pragma once

char* makeFilename(char* filename, int filecnt) {
	
	char toint[10];
	_itoa(filecnt, toint, 10);

	char* tmp = (char*)calloc(strlen(filename) + strlen(toint)+ 1, sizeof(char));			//tmp�� �� ���� "��ȣ��_" or "��ȣ��_" + filecnt�� ���� �� �̹Ƿ�, 4 + 11(10 + ��Ʈ�� �� ���� 1)
	if (tmp == NULL) {
		printf("�޸� �Ҵ� ����!\n");
		exit(1);
	}
	strcpy(tmp, filename);
	
	char* Name = (char*)calloc(strlen(filename) + 5, sizeof(char));							// .txt + 1
	if (Name == NULL) {
		printf("�޸� �Ҵ� ����!\n");
		exit(1);
	}
	strcat(tmp, toint);
	strcpy(Name, tmp);
	strcat(Name, ".txt");

	free(tmp);

	return Name;
}


//����ڰ� �Է��� ���� �̸��� �޾Ƽ� ������ �����ϴ��� �˻� ��, ������ �����Ѵٸ� �ش� ���� ������ ��ȯ��
char* fileRead(char* filename){

	FILE* fp = fopen(filename,"r");

	if (fp == NULL) {
		printf("ã�� ������ �����ϴ�.\n");
		return NULL;
	}

	//�о�� ������ ũ�� ����
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char* text = (char*)calloc(size + 1, sizeof(char));
	if (text == NULL) {
		printf("�޸� �Ҵ� ����!\n");
		exit(1);
	}

	fread(text, 1, size + 1 ,fp);

	fclose(fp);
	//text[size] = '\0';

	return text;
}

//����� ���� �̸��� �޾Ƽ� .txt ���Ϸ� ���, ����� ���� �̸��� ��ȯ��. ���� ������ ������ �ִٸ� ����ų� �̸� ������ ����, or ��� �۾��� ������� �����ϰ� ��. 
void fileWrite(char* filename, char* text) {

	FILE* fp = fopen(filename, "w");

	if (fp == NULL) {
		printf("�ش� ���丮�� ���� �� �� �����ϴ�.\n");
		return;
	}
	fputs(text, fp);

	fclose(fp);

	printf("%s ������ ����߽��ϴ�.\n", filename);
	return;
}


//��ġ ��ȣȭ�� �����ϴ� �Լ�, info �迭 �����͸� �޾Ƽ� ���������� key, keylen �ۼ� �� ��ȣ�� ����
char* encrypt(char* plaintext, encryptionInfo* info) {
	srand((unsigned int)(time(NULL) + rand()));

	int blankboxcnt;
	int textlen = strlen(plaintext);
	int keylen = generateKeylen(textlen);
	int* key = generateKey(keylen);

	if (key == NULL) {
		printf("�޸� �Ҵ� ����\n");
		return NULL;
	}

	info->key = key;
	info->keylen = keylen;

	//blankbox�� ������ ���ϴ� ����.
	//text>key , text == key, text < key�� �� ��츦 ��� �����ؾ��Ѵ�.
	//�⺻������ key ���̺��� text�� ��ٸ� keylen ���� text % key ���� ���ָ� �ȴ�.
	//�ݴ��� ��Ȳ�� �����ϰ� key���� text ���̸� ���ָ� �ȴ�.
	if(textlen > keylen) {
		blankboxcnt = keylen - (textlen % keylen);
	}
	else if (textlen == keylen) {
		blankboxcnt = 0;
	}
	else {
		blankboxcnt = keylen - textlen; 
	}
	
	//���� blankbox ó���� ���ش�.
	if (blankboxcnt) {
		char* blank = (char*)calloc(blankboxcnt + 1, sizeof(char));

		if (blank == NULL) {
			printf("�޸� �Ҵ� ����.\n");
			exit(1);
		}

		for (int i = 0; i < blankboxcnt; ++i) {
			int setrand = rand() % 2;															//�빮�� or �ҹ��� ������ ���� ����
			if (setrand) blank[i] = rand() % 26 + 'a';
			else blank[i] = rand() % 26 + 'A';													//0�̸� �빮��, 1�̸� �ҹ���
		}

		blank[blankboxcnt] = '\0';
		info->blankbox = blankboxcnt;

		char* tmp = (char*)calloc(textlen + blankboxcnt + 1, sizeof(char));
		if (tmp == NULL) {
			printf("�޸� �Ҵ� ����.\n");
			exit(1);
		}

		strcpy(tmp,plaintext);
		strcat(tmp,blank);

		free(plaintext);
		free(blank);

		plaintext = tmp;
	}
	else info->blankbox = 0;

	textlen = strlen(plaintext);

	char* cipertext = (char*)calloc(textlen + 1, sizeof(char));
	if (cipertext == NULL) {
		printf("�޸� �Ҵ� ����.\n");
		exit(1);
	}

	char* buffer = (char*)calloc(keylen + 1, sizeof(char));
	if (buffer == NULL) {
		printf("�޸� �Ҵ� ����.\n");
		exit(1);
	}

	for (int i = 0; i < textlen; i += keylen) {
		for (int j = 0; j < keylen; ++j) {
			if (i + j < textlen) {
				buffer[j] = plaintext[key[j] + i];
			}
			else {
				buffer[j] = '\0';
			}
		}
		strncat(cipertext, buffer, keylen);
	}
	cipertext[textlen] = '\0';

	free(buffer);
	free(plaintext);
	
	plaintext = NULL;

	return cipertext;
}


//��ġ ��ȣȭ�� �����ϴ� �Լ�, info �迭 �����͸� �޾Ƽ� ���������� key ��Ī, ��ȣȭ
//���α׷� ���� ���� ��ȣȭ �� �����̳�, ���� �� ������ ������ ��ȣȭ �Ұ�
//�� ���α׷��� ���� ��ȣȭ�� �մ� ���α׷��� �����ǵ��� �ƴϹǷ�, �������� ���� Ű ����/��ȣȭ�� �������� ����
char* decryption(char* cipertext, encryptionInfo* info) {
	
	if (info == NULL) {
		printf("���� ����ü�� ����������.\n");
		return NULL;
	}

	int* encryptkey = info->key;
	int keylen = info->keylen;
	int blankbox = info->blankbox;
	int textlen = strlen(cipertext);

	int* decryptionkey = (int*)calloc(keylen, sizeof(int));
	if (decryptionkey == NULL) {
		printf("�޸� �Ҵ� ����.\n");
		return NULL;
	}
	for (int i = 0; i < keylen; ++i) {
		decryptionkey[encryptkey[i]] = i;				//��ȣȭŰ�� ��ȣȭŰ�� ��Ī������ �̿��Ͽ� ��ȣȭ Ű ����
	}

	char* plaintext = (char*)calloc(textlen + 1, sizeof(char));
	if (plaintext == NULL) {
		printf("�޸� �Ҵ� ����.\n");
		return NULL;
	}

	char* buffer = (char*)calloc(keylen + 1, sizeof(char));
	if (buffer == NULL) {
		printf("�޸� �Ҵ� ����.\n");
		exit(1);
	}
	
	//��ȣȭ ����
	for (int i = 0; i < textlen; i += keylen) {
		for (int j = 0; j < keylen; ++j) {
			if (i + j < textlen) {
				buffer[j] = cipertext[decryptionkey[j] + i];
			}
			else {
				buffer[j] = '\0';
			}
		}
		strncat(plaintext, buffer, keylen);
	}
		plaintext[textlen] = '\0';

		free(decryptionkey);
		free(cipertext);

		if (blankbox) {								//blankbox != 0 �̶�� ù��° blankbox ��ġ�� ���ڿ��� �η� �ٲ۴�.
			plaintext[textlen - blankbox] = '\0';
			char* tmp = (char*)calloc(strlen(plaintext) + 1, sizeof(char));		//���� ����Ǵ� ������ �� �Ҵ�

			if (tmp == NULL) {
				printf("�޸� �Ҵ� ����.\n");
				exit(1);
			}
			strncpy(tmp, plaintext, strlen(plaintext) + 1);

			free(plaintext);
			plaintext = tmp;
			return plaintext;
		}

		return plaintext;
	}


int generateKeylen(int textlen) {

	if (textlen <= 50) return 5;
	else if (textlen <= 100) return 10;
	else if (textlen <= 200) return 15;
	else return 20;
}

//���� ���̿� ���� Ű ���̸� �ް� ��ȣȭ�� ���� Ű�� ����
int* generateKey(int keylen) {
	srand((unsigned int)(time(NULL) + rand()));

	//keylen ���� ��ŭ�� key�迭�� 0~keylen - 1������ ���ڰ� �ѹ� �� ���� �ϰ�, ��ġ�� �����̾�� ��.
	int* key = (int*)calloc(keylen, sizeof(int));

	if (key == NULL) {
		printf("key ���� ����.\n");
		return NULL;
	}

	int pos;

	for (int i = 0; i < keylen; ++i) {
		do {
			pos = (rand() % keylen);
			if (pos == keylen) continue;			//index == keylen �̶�� �迭�� ����Ƿ� ���ܼ���
			if (key[pos] == NULL) break;
		} while (1);
		key[pos] = i;
	}
	return key;
}

//�迭 ũ�⸦ üũ�Ѵ�, �迭�� ���� �̿������� �迭�� �ʱ�ȭ �Ҷ� �η� �ʱ�ȭ �ϰų� calloc�� �����Ҵ��� �����Ѵ�.
//�迭�� ���� �̻� �������� �迭����� �ι�� ���Ͽ� ũ�⸦ Ű���, ���� �迭�� �����Ѵ�.
encryptionInfo* checkArray(encryptionInfo* info, int* arrsize) {
	if (info == NULL) return info;							//ó�� ���� NULL�̶�� �� �����Ͱų� NULL������

	int cnt = 0;
	while (cnt < *arrsize && info[cnt].filename != NULL) {
		cnt++;
	}

	//�� �Ҵ��ϴ� ����
	if (cnt >= *arrsize / 2) {
		encryptionInfo* tmp = (encryptionInfo*)calloc(*arrsize * 2, sizeof(encryptionInfo));
		if (tmp == NULL) {
			printf("�޸� �Ҵ� ����\n");
			exit(1);
		}
		for (int i = 0; i < cnt; ++i) {
			tmp[i] = info[i];
		}
		free(info);

		info = tmp;
		*arrsize *= 2;
	}

	return info;
}



//��ȣȭ �Ѱ� �Լ�, \n or ���� ��ȣȭ ��� ����, ��ȣȭ ���� �� �� ��ȣȭ �� ���� ���� or ���� �޴� ����
encryptionInfo* toCiper(encryptionInfo* info, int* filecnt,int* arrcnt) {
	
	int state;
	int textlen;

	char* cipertext = NULL;
	char* plaintext = NULL;
	char* Name = NULL;

	char filename[100] = { -1 };
	char* cipername = "��ȣ��_\0";

	do {
		state = 0;

		printf("��ȣȭ ����� �����ϼ���.\n");
		printf("1. �� �ٲ� ���� ��ȣȭ\n");
		printf("2. ���� ��ü ��ȣȭ\n");

		printf("�Է� : ");
		scanf(" %d", &state);
		getchar();

		if (state > 2) {
			printf("�߸� �� �Է��Դϴ�.\n");
		}
		else {
			break;
		}
	} while (1);

	printf("��ȣȭ �� ���� �̸� �Է� : ");
	fgets(filename, 100, stdin);
	filename[strlen(filename) - 1] = '\0';

	plaintext = fileRead(filename);


	if (plaintext == NULL) return;
	
	switch (state) {
	case 1: {
		//plaintext�� ���� curr �����Ϳ� \n�� �߰��� ������ ��ġ�� �����ϴ� begin �����͸� �̿��Ͽ�
		//���ۿ� �ؽ�Ʈ�� ����->�ٿ��ֱ⸦ �ϰ�, �ش� ���۸� ��ȣȭ.

		char* buf = NULL;
		char* begin = plaintext;
		char* curr = begin;

		textlen = strlen(plaintext);

		for (int i = 0; i <= textlen + 1; ++i) {
			if (*curr == '\n' || *curr == '\0') {

				buf = (char*)calloc((curr - begin) + 1, sizeof(char));
				cipertext = (char*)calloc((curr - begin) + 1, sizeof(char));

				if (buf == NULL) {
					printf("�޸� �Ҵ� ����!\n");
					exit(1);
				}

				strncpy(buf, begin, (curr - begin));
				buf[curr - begin] = '\0';

				cipertext = encrypt(buf, &info[*filecnt]);					//filecnt = 0 �̶��, �ε��� 0�� �����ϰ�

				Name = makeFilename(cipername, (*filecnt + 1));				//�̸��� ��ȣ��_1.txt �������� ����ؾ� �Ѵ�.

				fileWrite(Name, cipertext);

				info[*filecnt].filename = (char*)calloc(strlen(Name) + 1, sizeof(char));
				if (!info[*filecnt].filename) {
					printf("�޸� �Ҵ� ����!\n");
					exit(1);
				}

				info[*filecnt].filename = strcpy(info[*filecnt].filename, Name);

				//printf("��ȣ�� �̸� : %s\n", info[*filecnt].filename);

				*filecnt = *filecnt + 1;

				info = checkArray(info, arrcnt);

				//printf("�迭 ũ�� : %d\n", *arrcnt);

				if (info == NULL) {
					printf("�޸� �Ҵ� ����.\n");
					return;
				}

				printf("��ȣȭ �Ϸ�\n");
				printf("��ȣ�� : %s\n", cipertext);

				Name = NULL;
				free(cipertext);

				if (plaintext[i] == '\0') { break; }

				
				i++;
				curr++;
				begin = curr;

			}
			else {
				curr++;
			}
		}
		printf("��ȣȭ ���� ���� �Ϸ�\n");
		free(plaintext);

		begin = curr = NULL;

		break;
	}
	case 2: {
		//���� ��ȣȭ

		textlen = strlen(plaintext);

		cipertext = (char*)calloc(textlen + 1, sizeof(char));
		cipertext = encrypt(plaintext, &info[*filecnt]);

		Name = makeFilename(cipername, *filecnt + 1);

		fileWrite(Name,cipertext);

		info[*filecnt].filename = (char*)calloc(strlen(Name) + 1, sizeof(char));
	

		if (!info[*filecnt].filename) {
			printf("�޸� �Ҵ� ����!\n");
			exit(1);
		}

		info[*filecnt].filename = strcpy(info[*filecnt].filename, Name);
		info[*filecnt].filename[strlen(Name)] = '\0';
		printf("��ȣ�� �̸� : %s\n", info[*filecnt].filename);
		printf("%s\n", info[0].filename);
		*filecnt++;

		info = checkArray(info, arrcnt);
		printf("�迭 ũ�� : %d\n", *arrcnt);
		if (info == NULL) {
			printf("��ȣȭ ����.\n");
			return;
		}

		printf("��ȣȭ �Ϸ�\n");
		printf("��ȣ�� : %s\n", cipertext);

		free(cipertext);

		cipertext = NULL;
		Name = NULL;

		break;
	}
		default:
			break;
	}
	return info;
}

//��ȣȭ �Ѱ� �Լ�, ���� ī��Ʈ, �迭 ������ ������ ����.
//����ڿ��� ���� �̸��� �ް� �������� �ʴ´ٸ� ���θ޴��� �ٽ� ���ư�.
encryptionInfo* toPlain(encryptionInfo* info, int* filecnt, int* arrcnt){

	char* cipertext = NULL;
	char* Name = NULL;
	char* plaintext = NULL;

	char filename[100] = { -1 };
	char* encryptname = "��ȣ��_\0";

	printf("��ȣȭ �� ���� ���� �Է��ϼ���.\n");
	printf("�Է� : ");
	getchar();
	fgets(filename, 100, stdin);
	filename[strlen(filename) - 1] = '\0';

	cipertext = fileRead(filename);
	if (cipertext == NULL) return;

	for (int i = 0; i < *arrcnt; ++i) {
		if (info[i].filename != NULL) {
			if (strcmp(info[i].filename, filename) == 0) {
				plaintext = decryption(cipertext, &info[i]);
				break;
			}
		}
		else if (info[i].filename == NULL) {
			printf("ã�� ������ �����ϴ�.");
			return info;
		}
	}

	Name = makeFilename(encryptname, *filecnt + 1);

	fileWrite(Name,plaintext);

	*filecnt = *filecnt + 1;

	info = checkArray(info, arrcnt);

	printf("��ȣȭ �Ϸ�\n");
	printf("��ȣ�� : %s\n", plaintext);

	free(plaintext);

	return info;
}


//���α׷��� ��ü�� ���, ��ȣȭ�� ���� Info ����ü�� �����ϴ� �迭�� ����
//Info ����ü�� ��ȣȭ �� ���ϸ�, key, key���̸� ����
//��ȣȭ�� ������ �Է��� ���� �̸��� Ž���� ��, �ش� ������ ��ȣȭ �Լ��� �����Ͽ� ��ȣȭ ����
//Ž���� �̿��ϱ⿡ ����ü�� ������ �����ϴ� ������ ���� �����, �迭�� �̿��� �� tree�� ����� �� �����ϴ���
//�ش� �ڵ�� ���� ����� �� SOLID ��Ģ�� �°� �ۼ������� �ִ��� ������ ��� ���� �� ��Ȳ�� �����Ͽ� �ۼ���
void transpositionCiper() {

	int arraysize = 2;
	int input = 0;

	int enfileCnt = 0;		//��ȣȭ_���� ���� ���� ����� ���� ����
	int defileCnt = 0;		//��ȣȭ_���� ���� ���� ����� ���� ����

	//�迭�� �̿��� ����� ����Ѵٸ�, �迭�� ũ�⸦ üũ�ϴ� ������ �迭�� ���� �̻��� �����Ͱ� ���ٸ� relloc�� �迭�� �ι� ũ�⸦ �ٽ� �Ҵ�
	encryptionInfo* info = (encryptionInfo*)calloc(arraysize, sizeof(encryptionInfo));

	while (input != 3) {

		printf("===============================================\n");

		printf("1. ��ȣȭ\n");
		printf("2. ��ȣȭ\n");
		printf("3. ����\n");

		printf("===============================================\n");

	
		printf("�Է� : ");
		scanf("%d", &input);

		switch (input)
		{
		case 1:
			info = toCiper(info, &enfileCnt, &arraysize);

			break;

		case 2:
			info = toPlain(info,&defileCnt, &arraysize);

			break;
		case 3:
			printf("���α׷� ����.\n");
			printf("===============================================\n");
			break;

		default:
			printf("�߸��� �Է��Դϴ�.");
			break;
		}
	}
}