#include "functions.h"

//디버깅 겸용 함수 보완, 예외처리 or 예외시 올바른 예외 출력 및 올바른 결과를 도출 하는지 테스트용 간단한 함수들로 시험.

//메인 함수에 들어갈 함수 본체, transpositionCiper()의 경우 각각 경우의 총괄 함수를 둘 가진다. 즉, 디버깅을 하기엔 규모가 너무 거대하다.
//그렇기에 프로그램의 본질적인 부분부터 테스트 한다. 구현의 대부분은 파일 입/출력을 받아서 다시 char 포인터를 반환하지만, 굳이 파일 입출력이 존재하지 않고 따로 
//string과 구조체를 선언 해 주어도 크게 문제가 없다.
//따라서 우선적으로 암호화 / 복호화가 정상적으로 이루어지는지 확인한다.


//암호화를 하기 전, 암호화를 담당하는 함수 encrypt의 경우 캡슐화를 위해 내부적으로 키의 값을 확인하고, 키를 생성하여 암호화 한 뒤, 받은 구조체에 정보를 입력한다.
//key 길이를 작성하는 함수는 복잡하지 않다, 다만 key를 만드는 함수인 generateKey()의 경우는 다르다. 랜덤한 위치에 한 번씩 0~keylen -1 값이 들어가야 한다.
//이를 만족하는가?
void test_1() {
	//generateKey는 키 길이를 받아서 받은 길이만큼 메모리를 동적 할당한다. 이 과정이 문제 없이 이루어지는가?
	//예측되는 결과는 int[5]에서 0~4까지의 값이 랜덤하게 가지고 있는 배열 포인터를 출력한다.

	int* iskey = generateKey(5);
	for(int i = 0; i < 5; ++i)
		printf("%d ", iskey[i]);

	free(iskey);

}	//결과, 문제없이 작동함을 확인했다.

//암호화 함수인 encrypt의 테스트를 확인한다.
//위에서 언급했듯, key를 내부적으로 생성하기에 명시적으로 확인할 방법은 없지만, 이는 따로 구조체를 할당함으로써 가능해진다.
//첫번째 테스트로는 blankbox가 없는 상황, 즉 평문 = keylen 의 상황을 테스트 할 것이다.
//keylen의 경우, 50자 이내의 길이는 10의 키 길이를 가지므로, 10의 길이를 갖는 텍스트를 준비하고 암호화 한다.

void test_2() {
	//예측되는 결과로는 a~j의 값이 반복없이 랜덤한 배열로 출력.
	//일어날 수 있는 예외로는 calloc 실패로 인한 에러 출력이 있다.(메모리 부족상황..!)

	encryptionInfo isinfo;
	char text[] = "abcdefghij\0";
	char* testresult;

	char* plain = (char*)malloc((strlen(text) + 1) * sizeof(char));
	plain = strcpy(plain, text);

	printf("%s\n", plain);

	isinfo.filename = "istest!";
	testresult = encrypt(plain, &isinfo);

	if (testresult == NULL) {
		printf("메모리 할당 오류를 감지 완료.\n");
		return;
	}

	printf("%s\n", testresult);
	printf("%d\n", isinfo.keylen);
	printf("%s\n", isinfo.filename);

	for (int i = 0; i < isinfo.keylen; ++i) {
		printf("%d ", isinfo.key[i]);
	}
	return;
}	//결과 : 문제없이 작동하지만, 입 출력을 동반하게 설계를 했기에 기본적으로 집어넣는 텍스트에는 동적할당을 해 줄 필요가 있다.


//이어서 복호화 함수인 decryption 테스트를 진행한다.
//이 프로그램의 복호화는 info 구조체에 암호화시 평문을 바꾼 정보들이 들어있으므로, 여기선 복호화를 위한 구조체를 따로 지정하여 테스트한다.
//이전의 테스트와 같이 blankbox가 없는 상황부터 검증한다.
void test_3() {
	//예측되는 결과, 복호화 키는 내부에서 동적할당 되고 free 과정을 함으로 구조체의 암호 데이터가 손상될 상황이 나오지 않는다.
	//즉, 암호화 했던 파일을 복호화 한다고 해당 정보가 소실되지 않는다. 물론 이는 프로그램 종료를 하지 않았다는 가정이다.
	//예측되는 에러, 예외상황으론 키의 정보가 존재하지 않을 때, 내부적으로 calloc/realloc 함수 진행시 메모리 할당 오류가 있다면 함수를 벗어나고 에러를 출력해야 한다.
	encryptionInfo info;
	int key[] = { 5,7,8,9,2,4,3,1,0,6 };
	char text[] = "fhijcedbag\0";
	char* testresult;

	info.blankbox = 0;
	info.filename = "istest";
	info.keylen = 10;
	info.key = key;

	char* cipher = (char*)malloc((strlen(text) + 1) * sizeof(char));
	strcpy(cipher, text);

	testresult = decryption(cipher, &info);

	printf("%s", testresult);
	//결과 : 암호키를 대칭하여 복호키를 정상적으로 생성했으며, 이 결과로 멀쩡한 평문이 출력되었음.
}

//blankbox가 존재하지 않는 상황의 암/복호화는 정상적으로 진행되었으므로, 이어서 암/복호화의 blankbox가 있는 경우도 검증한다.
//평문이 key보다 긴 경우, 평문이 key보다 짧은 경우 모두 테스트한다.
void test_4() {
	encryptionInfo* info = (encryptionInfo*)calloc(3, sizeof(encryptionInfo));

	char _text[] = "abcdefghij\0";
	char text[] = "abcd\0";
	char text_[] = "abcdefghijkl\0";

	char* _plain = (char*)calloc((strlen(_text) + 1),sizeof(char));
	char* plain = (char*)calloc((strlen(text) + 1),sizeof(char));
	char* plain_ = (char*)calloc((strlen(text_) + 1), sizeof(char));

	strcpy(_plain,_text);
	strcpy(plain, text);
	strcpy(plain_, text_);

	_plain = encrypt(_plain, &info[0]);
	plain = encrypt(plain, &info[1]);
	plain_ = encrypt(plain_, &info[2]);

	printf("%s\n", _plain);
	printf("%d\n", info[0].keylen);

	for (int i = 0; i < info[0].keylen; ++i) {
		printf("%d ", info[0].key[i]);
	}
	printf("\n");
	printf("===============================\n");

	printf("%s\n", plain);
	printf("%d\n", info[1].keylen);

	for (int i = 0; i < info[1].keylen; ++i) {
		printf("%d ", info[1].key[i]);
	}
	printf("\n");
	printf("===============================\n");

	printf("%s\n", plain_);
	printf("%d\n", info[2].keylen);

	for (int i = 0; i < info[2].keylen; ++i) {
		printf("%d ", info[2].key[i]);
	}
	printf("\n");
	printf("===============================\n");


	_plain = decryption(_plain, &info[0]);
	plain = decryption(plain, &info[1]);
	plain_ = decryption(plain_, &info[2]);

	printf("%s\n", _plain);
	printf("%s\n", plain);
	printf("%s\n", plain_);

}	//결과 : 암호화 / 복호화 로직 오류를 발견하여 개선 완료, 정상적으로 암호화 / 복호화에 성공하였고, blankbox로 낭비되던 메모리까지 재 할당하는데 성공했다.

//우리는 구조체 배열을 받아서 암호화,복호화 함수에게 넘겨 줄 것이다.
//만약 이 과정에서 구조체 배열이 가득 찬다면 어떡 할 것인가?
//다만 암호화, 복호화 함수에는 그 기능을 넣지 않았다. 그렇게 되면 암호화/복호화 함수의 일이 더 늘어나는 셈이며, 암호화/복호화 하는 과정에 들어간다곤 볼 수 없다.
//따라서 암호화/복호화 후 배열을 검사하는 함수를 사용하기로 결정했다. 
//그리고 그 검사가 제대로 작동하는지 테스트 할 것이다.
void test_5() {
	int arrsize = 2;
	encryptionInfo* info = (encryptionInfo*)calloc(arrsize, sizeof(encryptionInfo));

	encryptionInfo first;
	first.filename = "first\0";
	info[0] = first;

	printf("%s\n", info[0].filename);

	info = checkArray(info,&arrsize);

	encryptionInfo second;
	second.filename = "second\0";
	info[1] = second;

	printf("%d\n", arrsize);
	printf("%s\n", info[0].filename);
	printf("%s\n", info[1].filename);

	info = checkArray(info, &arrsize);

	printf("%d\n", arrsize);

}	// 결과 : 정상적으로 arrsize의 값을 두배로 만들고 크기도 두배로 재 할당 하는 모습을 보인다. 구조체 재 할당이 calloc로 이루어 지므로, file의 개수를 내부적으로도 처리가 가능하다.
//다만, 파일을 추가하는 행위 자체는 사용자가 다루기엔 위험하며, 삽입함수를 이용하지 않기에 위험할 수 있다. 이는 접근자를 이용하여 간단하게 막을 수 있지만 c에서는 불가능하다.

//이제 거의 다 왔다. 입 출력은 사실 크게 어려운 함수가 아니므로, 입 출력을 위한 파일 이름을 만들어주는 변수를 우선 테스트한다.
//해당 함수가 제일 만들기 까다로웠다. 파일이 많아지면 자연스럽게 파일 이름 뒤에 붙을 숫자가 많아진다.
//이를 char로 처리하기엔 무리가 있다. 자릿수가 변하는 연산부터 머리 아프다, 그래서 int를 이용해 파일 개수를 세고, 암호화/복호화를 할 때 파일 이름을 출력 함수에게 넘겨주게 될 것이다.
//이를 이용하여 암호화/복호화 시 "암호화_" "복호화_" 스트링을 미리 배정해 두고, 이 뒤에 파일 개수 정보를 저장하는 int 변수를 char 형태로 변환시키고 strcat을 이용하여 붙여준다.
//다만, itoa 함수의 경우는 visual studio 내에서 밖에 작동하지 않으므로 다른 환경에서 사용할 땐 직접 itoa 함수를 구현할 필요가 있다.
void test_6() {
	char name[] = "테스트_\0";
	int cnt = 1;

	char* Name = NULL;

	Name = makeFilename(name, cnt);
	if (Name == NULL) {
		printf("크아악\n");
		exit(1);
	}

	printf("%s", Name);
} //결과 : 아주 잘 뽑아 준다. 나중에 입출력 함수에 바로 집어 넣을 예정인 지라, 파일명 뒤에 .txt가 붙는다.


//입출력 함수를 테스트 할 때가 왔다.
//일단 기본적으로 위의 모든 케이스를 통과했으므로, 바로 암호화 / 복호화를 실행하겠다.
//예측되는 예외 케이스는 메모리 할당 오류, 악의적 입력, 복호화시 널 포인터 받았을 때 처리, 등 설계 때 부터 생각해둔 대다수의 오류가 검증되었다.
//유니코드 / 암호문 만 있을 때 복호화 방식은 배제하였다.
void test_7() { //예상되는 결과 : 프로젝트 내에 test.txt를 읽어서 제대로 출력하는지 확인 할 것이다, 파일 읽기/쓰기가 문제 없다면 이후 테스트는 최종 테스트가 된다.

	char* text = fileRead("test.txt");
	printf("%s\n", text);

	fileWrite("test_output.txt",text);

}	//결과 : 매우 잘 나온다.

//총괄 함수들인 toCiper, toPlain의 차례가 왔다.
//최대한 기능 분리를 했다곤 생각하지만 그래도 코드 덩치가 커지는 건 아직 실력이 부족한 탓에 더 줄이기에는 시간과 의지가 따라주지 않았다.
//아무튼, 이 함수 검증이 끝난다면 본체 함수에서 입력이 꼬이지 않는 이상 버그와 예외상황은 없다고 예측된다.
void test_8() {
	int fileCnt = 1;
	int arrsize = 2;
	int* pc = &fileCnt;
	int* ac = &arrsize;
	encryptionInfo* info = (encryptionInfo*)calloc(arrsize, sizeof(encryptionInfo));

	toCiper(info, &fileCnt, &arrsize);

	toPlain(info, &fileCnt, &arrsize);

	//결과 : 덩치가 큰 만큼 생각보다 많은 오류가 있었고, 아직 개발 실력이 미숙한 것을 크게 체감한다.
	//문자열과 textlen 부분의 인덱스 계산에 오류가 있어서 수정하였다. toCiper의 두 모드 완벽 동작을 확인했다.
	//toPlain이 이름을 읽어오지 못 하던 오류도 개선했다.
}


int main() {

	//test_1();
	//test_2();
	//test_3();
	//test_4();
	//test_5();
	//test_6();
	//test_7();
	//test_8();
	
	return 0;
}