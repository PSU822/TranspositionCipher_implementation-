#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include"predeclaration.h"


#pragma once

char* makeFilename(char* filename, int filecnt) {
	
	char toint[10];
	_itoa(filecnt, toint, 10);

	char* tmp = (char*)calloc(strlen(filename) + strlen(toint)+ 1, sizeof(char));			//tmp에 들어갈 내용 "암호문_" or "복호문_" + filecnt의 현재 값 이므로, 4 + 11(10 + 스트링 끝 문자 1)
	if (tmp == NULL) {
		printf("메모리 할당 오류!\n");
		exit(1);
	}
	strcpy(tmp, filename);
	
	char* Name = (char*)calloc(strlen(filename) + 5, sizeof(char));							// .txt + 1
	if (Name == NULL) {
		printf("메모리 할당 오류!\n");
		exit(1);
	}
	strcat(tmp, toint);
	strcpy(Name, tmp);
	strcat(Name, ".txt");

	free(tmp);

	return Name;
}


//사용자가 입력한 파일 이름을 받아서 파일이 존재하는지 검사 후, 파일이 존재한다면 해당 파일 내용을 반환함
char* fileRead(char* filename){

	FILE* fp = fopen(filename,"r");

	if (fp == NULL) {
		printf("찾는 파일이 없습니다.\n");
		return NULL;
	}

	//읽어올 파일의 크기 측정
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char* text = (char*)calloc(size + 1, sizeof(char));
	if (text == NULL) {
		printf("메모리 할당 오류!\n");
		exit(1);
	}

	fread(text, 1, size + 1 ,fp);

	fclose(fp);
	//text[size] = '\0';

	return text;
}

//출력할 파일 이름을 받아서 .txt 파일로 출력, 출력한 파일 이름을 반환함. 만약 동일한 파일이 있다면 덮어쓰거나 이름 변경을 선택, or 모든 작업을 취소할지 선택하게 함. 
void fileWrite(char* filename, char* text) {

	FILE* fp = fopen(filename, "w");

	if (fp == NULL) {
		printf("해당 디렉토리에 접근 할 수 없습니다.\n");
		return;
	}
	fputs(text, fp);

	fclose(fp);

	printf("%s 파일을 출력했습니다.\n", filename);
	return;
}


//전치 암호화를 수행하는 함수, info 배열 포인터를 받아서 내부적에서 key, keylen 작성 후 암호문 리턴
char* encrypt(char* plaintext, encryptionInfo* info) {
	srand((unsigned int)(time(NULL) + rand()));

	int blankboxcnt;
	int textlen = strlen(plaintext);
	int keylen = generateKeylen(textlen);
	int* key = generateKey(keylen);

	if (key == NULL) {
		printf("메모리 할당 오류\n");
		return NULL;
	}

	info->key = key;
	info->keylen = keylen;

	//blankbox의 개수를 정하는 과정.
	//text>key , text == key, text < key의 세 경우를 모두 생각해야한다.
	//기본적으로 key 길이보다 text가 길다면 keylen 에서 text % key 값을 빼주면 된다.
	//반대의 상황은 간단하게 key에서 text 길이를 빼주면 된다.
	if(textlen > keylen) {
		blankboxcnt = keylen - (textlen % keylen);
	}
	else if (textlen == keylen) {
		blankboxcnt = 0;
	}
	else {
		blankboxcnt = keylen - textlen; 
	}
	
	//이후 blankbox 처리를 해준다.
	if (blankboxcnt) {
		char* blank = (char*)calloc(blankboxcnt + 1, sizeof(char));

		if (blank == NULL) {
			printf("메모리 할당 실패.\n");
			exit(1);
		}

		for (int i = 0; i < blankboxcnt; ++i) {
			int setrand = rand() % 2;															//대문자 or 소문자 선택을 위한 변수
			if (setrand) blank[i] = rand() % 26 + 'a';
			else blank[i] = rand() % 26 + 'A';													//0이면 대문자, 1이면 소문자
		}

		blank[blankboxcnt] = '\0';
		info->blankbox = blankboxcnt;

		char* tmp = (char*)calloc(textlen + blankboxcnt + 1, sizeof(char));
		if (tmp == NULL) {
			printf("메모리 할당 실패.\n");
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
		printf("메모리 할당 실패.\n");
		exit(1);
	}

	char* buffer = (char*)calloc(keylen + 1, sizeof(char));
	if (buffer == NULL) {
		printf("메모리 할당 실패.\n");
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


//전치 복호화를 수행하는 함수, info 배열 포인터를 받아서 내부적으로 key 대칭, 복호화
//프로그램 실행 전에 암호화 된 파일이나, 종료 후 생성된 파일은 복호화 불가
//이 프로그램은 정보 암호화를 뚫는 프로그램의 설계의도가 아니므로, 공격으로 인한 키 유추/복호화는 상정하지 않음
char* decryption(char* cipertext, encryptionInfo* info) {
	
	if (info == NULL) {
		printf("받은 구조체가 널포인터임.\n");
		return NULL;
	}

	int* encryptkey = info->key;
	int keylen = info->keylen;
	int blankbox = info->blankbox;
	int textlen = strlen(cipertext);

	int* decryptionkey = (int*)calloc(keylen, sizeof(int));
	if (decryptionkey == NULL) {
		printf("메모리 할당 실패.\n");
		return NULL;
	}
	for (int i = 0; i < keylen; ++i) {
		decryptionkey[encryptkey[i]] = i;				//암호화키와 복호화키는 대칭형임을 이용하여 복호화 키 생성
	}

	char* plaintext = (char*)calloc(textlen + 1, sizeof(char));
	if (plaintext == NULL) {
		printf("메모리 할당 실패.\n");
		return NULL;
	}

	char* buffer = (char*)calloc(keylen + 1, sizeof(char));
	if (buffer == NULL) {
		printf("메모리 할당 실패.\n");
		exit(1);
	}
	
	//복호화 수행
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

		if (blankbox) {								//blankbox != 0 이라면 첫번째 blankbox 위치의 문자열을 널로 바꾼다.
			plaintext[textlen - blankbox] = '\0';
			char* tmp = (char*)calloc(strlen(plaintext) + 1, sizeof(char));		//이후 낭비되는 공간을 재 할당

			if (tmp == NULL) {
				printf("메모리 할당 실패.\n");
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

//평문의 길이에 따른 키 길이를 받고 암호화에 쓰일 키를 만듬
int* generateKey(int keylen) {
	srand((unsigned int)(time(NULL) + rand()));

	//keylen 길이 만큼의 key배열에 0~keylen - 1까지의 숫자가 한번 씩 들어가야 하고, 위치는 랜덤이어야 함.
	int* key = (int*)calloc(keylen, sizeof(int));

	if (key == NULL) {
		printf("key 생성 실패.\n");
		return NULL;
	}

	int pos;

	for (int i = 0; i < keylen; ++i) {
		do {
			pos = (rand() % keylen);
			if (pos == keylen) continue;			//index == keylen 이라면 배열을 벗어나므로 예외설정
			if (key[pos] == NULL) break;
		} while (1);
		key[pos] = i;
	}
	return key;
}

//배열 크기를 체크한다, 배열의 널을 이용함으로 배열을 초기화 할땐 널로 초기화 하거나 calloc로 동적할당을 권장한다.
//배열의 절반 이상 차있으면 배열사이즈를 두배로 곱하여 크기를 키우고, 이전 배열은 삭제한다.
encryptionInfo* checkArray(encryptionInfo* info, int* arrsize) {
	if (info == NULL) return info;							//처음 부터 NULL이라면 빈 포인터거나 NULL포인터

	int cnt = 0;
	while (cnt < *arrsize && info[cnt].filename != NULL) {
		cnt++;
	}

	//재 할당하는 과정
	if (cnt >= *arrsize / 2) {
		encryptionInfo* tmp = (encryptionInfo*)calloc(*arrsize * 2, sizeof(encryptionInfo));
		if (tmp == NULL) {
			printf("메모리 할당 에러\n");
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



//암호화 총괄 함수, \n or 전문 암호화 모드 선택, 암호화 종료 후 더 암호화 할 파일 선택 or 메인 메뉴 복귀
encryptionInfo* toCiper(encryptionInfo* info, int* filecnt,int* arrcnt) {
	
	int state;
	int textlen;

	char* cipertext = NULL;
	char* plaintext = NULL;
	char* Name = NULL;

	char filename[100] = { -1 };
	char* cipername = "암호문_\0";

	do {
		state = 0;

		printf("암호화 방식을 선택하세요.\n");
		printf("1. 줄 바꿈 마다 암호화\n");
		printf("2. 파일 전체 암호화\n");

		printf("입력 : ");
		scanf(" %d", &state);
		getchar();

		if (state > 2) {
			printf("잘못 된 입력입니다.\n");
		}
		else {
			break;
		}
	} while (1);

	printf("암호화 할 파일 이름 입력 : ");
	fgets(filename, 100, stdin);
	filename[strlen(filename) - 1] = '\0';

	plaintext = fileRead(filename);


	if (plaintext == NULL) return;
	
	switch (state) {
	case 1: {
		//plaintext를 읽을 curr 포인터와 \n을 발견할 때마다 위치를 갱신하는 begin 포인터를 이용하여
		//버퍼에 텍스트를 복사->붙여넣기를 하고, 해당 버퍼를 암호화.

		char* buf = NULL;
		char* begin = plaintext;
		char* curr = begin;

		textlen = strlen(plaintext);

		for (int i = 0; i <= textlen + 1; ++i) {
			if (*curr == '\n' || *curr == '\0') {

				buf = (char*)calloc((curr - begin) + 1, sizeof(char));
				cipertext = (char*)calloc((curr - begin) + 1, sizeof(char));

				if (buf == NULL) {
					printf("메모리 할당 오류!\n");
					exit(1);
				}

				strncpy(buf, begin, (curr - begin));
				buf[curr - begin] = '\0';

				cipertext = encrypt(buf, &info[*filecnt]);					//filecnt = 0 이라면, 인덱스 0에 저장하고

				Name = makeFilename(cipername, (*filecnt + 1));				//이름은 암호문_1.txt 형식으로 출력해야 한다.

				fileWrite(Name, cipertext);

				info[*filecnt].filename = (char*)calloc(strlen(Name) + 1, sizeof(char));
				if (!info[*filecnt].filename) {
					printf("메모리 할당 오류!\n");
					exit(1);
				}

				info[*filecnt].filename = strcpy(info[*filecnt].filename, Name);

				//printf("암호문 이름 : %s\n", info[*filecnt].filename);

				*filecnt = *filecnt + 1;

				info = checkArray(info, arrcnt);

				//printf("배열 크기 : %d\n", *arrcnt);

				if (info == NULL) {
					printf("메모리 할당 오류.\n");
					return;
				}

				printf("암호화 완료\n");
				printf("암호문 : %s\n", cipertext);

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
		printf("암호화 과정 전부 완료\n");
		free(plaintext);

		begin = curr = NULL;

		break;
	}
	case 2: {
		//전문 암호화

		textlen = strlen(plaintext);

		cipertext = (char*)calloc(textlen + 1, sizeof(char));
		cipertext = encrypt(plaintext, &info[*filecnt]);

		Name = makeFilename(cipername, *filecnt + 1);

		fileWrite(Name,cipertext);

		info[*filecnt].filename = (char*)calloc(strlen(Name) + 1, sizeof(char));
	

		if (!info[*filecnt].filename) {
			printf("메모리 할당 오류!\n");
			exit(1);
		}

		info[*filecnt].filename = strcpy(info[*filecnt].filename, Name);
		info[*filecnt].filename[strlen(Name)] = '\0';
		printf("암호문 이름 : %s\n", info[*filecnt].filename);
		printf("%s\n", info[0].filename);
		*filecnt++;

		info = checkArray(info, arrcnt);
		printf("배열 크기 : %d\n", *arrcnt);
		if (info == NULL) {
			printf("암호화 실패.\n");
			return;
		}

		printf("암호화 완료\n");
		printf("암호문 : %s\n", cipertext);

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

//복호화 총괄 함수, 파일 카운트, 배열 사이즈 정보를 받음.
//사용자에게 파일 이름을 받고 존재하지 않는다면 메인메뉴로 다시 돌아감.
encryptionInfo* toPlain(encryptionInfo* info, int* filecnt, int* arrcnt){

	char* cipertext = NULL;
	char* Name = NULL;
	char* plaintext = NULL;

	char filename[100] = { -1 };
	char* encryptname = "복호문_\0";

	printf("복호화 할 파일 명을 입력하세요.\n");
	printf("입력 : ");
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
			printf("찾는 파일이 없습니다.");
			return info;
		}
	}

	Name = makeFilename(encryptname, *filecnt + 1);

	fileWrite(Name,plaintext);

	*filecnt = *filecnt + 1;

	info = checkArray(info, arrcnt);

	printf("복호화 완료\n");
	printf("복호문 : %s\n", plaintext);

	free(plaintext);

	return info;
}


//프로그램의 본체를 담당, 복호화를 위한 Info 구조체를 저장하는 배열을 가짐
//Info 구조체는 암호화 시 파일명, key, key길이를 저장
//복호화시 유저가 입력한 파일 이름을 탐색한 후, 해당 정보를 복호화 함수에 전달하여 복호화 진행
//탐색을 이용하기에 구조체의 정보를 저장하는 데이터 구조 고민중, 배열을 이용할 지 tree를 사용할 지 생각하는중
//해당 코드는 과제 제출용 겸 SOLID 법칙에 맞게 작성됨으로 최대한 실제로 사용 했을 때 상황을 가정하여 작성중
void transpositionCiper() {

	int arraysize = 2;
	int input = 0;

	int enfileCnt = 0;		//암호화_숫자 파일 명을 만들기 위한 변수
	int defileCnt = 0;		//복호화_숫자 파일 명을 만들기 위한 변수

	//배열을 이용한 방식을 사용한다면, 배열의 크기를 체크하는 변수와 배열의 절반 이상의 데이터가 들어간다면 relloc로 배열의 두배 크기를 다시 할당
	encryptionInfo* info = (encryptionInfo*)calloc(arraysize, sizeof(encryptionInfo));

	while (input != 3) {

		printf("===============================================\n");

		printf("1. 암호화\n");
		printf("2. 복호화\n");
		printf("3. 종료\n");

		printf("===============================================\n");

	
		printf("입력 : ");
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
			printf("프로그램 종료.\n");
			printf("===============================================\n");
			break;

		default:
			printf("잘못된 입력입니다.");
			break;
		}
	}
}