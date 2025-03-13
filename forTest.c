#include "functions.h"

//����� ��� �Լ� ����, ����ó�� or ���ܽ� �ùٸ� ���� ��� �� �ùٸ� ����� ���� �ϴ��� �׽�Ʈ�� ������ �Լ���� ����.

//���� �Լ��� �� �Լ� ��ü, transpositionCiper()�� ��� ���� ����� �Ѱ� �Լ��� �� ������. ��, ������� �ϱ⿣ �Ը� �ʹ� �Ŵ��ϴ�.
//�׷��⿡ ���α׷��� �������� �κк��� �׽�Ʈ �Ѵ�. ������ ��κ��� ���� ��/����� �޾Ƽ� �ٽ� char �����͸� ��ȯ������, ���� ���� ������� �������� �ʰ� ���� 
//string�� ����ü�� ���� �� �־ ũ�� ������ ����.
//���� �켱������ ��ȣȭ / ��ȣȭ�� ���������� �̷�������� Ȯ���Ѵ�.


//��ȣȭ�� �ϱ� ��, ��ȣȭ�� ����ϴ� �Լ� encrypt�� ��� ĸ��ȭ�� ���� ���������� Ű�� ���� Ȯ���ϰ�, Ű�� �����Ͽ� ��ȣȭ �� ��, ���� ����ü�� ������ �Է��Ѵ�.
//key ���̸� �ۼ��ϴ� �Լ��� �������� �ʴ�, �ٸ� key�� ����� �Լ��� generateKey()�� ���� �ٸ���. ������ ��ġ�� �� ���� 0~keylen -1 ���� ���� �Ѵ�.
//�̸� �����ϴ°�?
void test_1() {
	//generateKey�� Ű ���̸� �޾Ƽ� ���� ���̸�ŭ �޸𸮸� ���� �Ҵ��Ѵ�. �� ������ ���� ���� �̷�����°�?
	//�����Ǵ� ����� int[5]���� 0~4������ ���� �����ϰ� ������ �ִ� �迭 �����͸� ����Ѵ�.

	int* iskey = generateKey(5);
	for(int i = 0; i < 5; ++i)
		printf("%d ", iskey[i]);

	free(iskey);

}	//���, �������� �۵����� Ȯ���ߴ�.

//��ȣȭ �Լ��� encrypt�� �׽�Ʈ�� Ȯ���Ѵ�.
//������ ����ߵ�, key�� ���������� �����ϱ⿡ ��������� Ȯ���� ����� ������, �̴� ���� ����ü�� �Ҵ������ν� ����������.
//ù��° �׽�Ʈ�δ� blankbox�� ���� ��Ȳ, �� �� = keylen �� ��Ȳ�� �׽�Ʈ �� ���̴�.
//keylen�� ���, 50�� �̳��� ���̴� 10�� Ű ���̸� �����Ƿ�, 10�� ���̸� ���� �ؽ�Ʈ�� �غ��ϰ� ��ȣȭ �Ѵ�.

void test_2() {
	//�����Ǵ� ����δ� a~j�� ���� �ݺ����� ������ �迭�� ���.
	//�Ͼ �� �ִ� ���ܷδ� calloc ���з� ���� ���� ����� �ִ�.(�޸� ������Ȳ..!)

	encryptionInfo isinfo;
	char text[] = "abcdefghij\0";
	char* testresult;

	char* plain = (char*)malloc((strlen(text) + 1) * sizeof(char));
	plain = strcpy(plain, text);

	printf("%s\n", plain);

	isinfo.filename = "istest!";
	testresult = encrypt(plain, &isinfo);

	if (testresult == NULL) {
		printf("�޸� �Ҵ� ������ ���� �Ϸ�.\n");
		return;
	}

	printf("%s\n", testresult);
	printf("%d\n", isinfo.keylen);
	printf("%s\n", isinfo.filename);

	for (int i = 0; i < isinfo.keylen; ++i) {
		printf("%d ", isinfo.key[i]);
	}
	return;
}	//��� : �������� �۵�������, �� ����� �����ϰ� ���踦 �߱⿡ �⺻������ ����ִ� �ؽ�Ʈ���� �����Ҵ��� �� �� �ʿ䰡 �ִ�.


//�̾ ��ȣȭ �Լ��� decryption �׽�Ʈ�� �����Ѵ�.
//�� ���α׷��� ��ȣȭ�� info ����ü�� ��ȣȭ�� ���� �ٲ� �������� ��������Ƿ�, ���⼱ ��ȣȭ�� ���� ����ü�� ���� �����Ͽ� �׽�Ʈ�Ѵ�.
//������ �׽�Ʈ�� ���� blankbox�� ���� ��Ȳ���� �����Ѵ�.
void test_3() {
	//�����Ǵ� ���, ��ȣȭ Ű�� ���ο��� �����Ҵ� �ǰ� free ������ ������ ����ü�� ��ȣ �����Ͱ� �ջ�� ��Ȳ�� ������ �ʴ´�.
	//��, ��ȣȭ �ߴ� ������ ��ȣȭ �Ѵٰ� �ش� ������ �ҽǵ��� �ʴ´�. ���� �̴� ���α׷� ���Ḧ ���� �ʾҴٴ� �����̴�.
	//�����Ǵ� ����, ���ܻ�Ȳ���� Ű�� ������ �������� ���� ��, ���������� calloc/realloc �Լ� ����� �޸� �Ҵ� ������ �ִٸ� �Լ��� ����� ������ ����ؾ� �Ѵ�.
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
	//��� : ��ȣŰ�� ��Ī�Ͽ� ��ȣŰ�� ���������� ����������, �� ����� ������ ���� ��µǾ���.
}

//blankbox�� �������� �ʴ� ��Ȳ�� ��/��ȣȭ�� ���������� ����Ǿ����Ƿ�, �̾ ��/��ȣȭ�� blankbox�� �ִ� ��쵵 �����Ѵ�.
//���� key���� �� ���, ���� key���� ª�� ��� ��� �׽�Ʈ�Ѵ�.
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

}	//��� : ��ȣȭ / ��ȣȭ ���� ������ �߰��Ͽ� ���� �Ϸ�, ���������� ��ȣȭ / ��ȣȭ�� �����Ͽ���, blankbox�� ����Ǵ� �޸𸮱��� �� �Ҵ��ϴµ� �����ߴ�.

//�츮�� ����ü �迭�� �޾Ƽ� ��ȣȭ,��ȣȭ �Լ����� �Ѱ� �� ���̴�.
//���� �� �������� ����ü �迭�� ���� ���ٸ� � �� ���ΰ�?
//�ٸ� ��ȣȭ, ��ȣȭ �Լ����� �� ����� ���� �ʾҴ�. �׷��� �Ǹ� ��ȣȭ/��ȣȭ �Լ��� ���� �� �þ�� ���̸�, ��ȣȭ/��ȣȭ �ϴ� ������ ���ٰ� �� �� ����.
//���� ��ȣȭ/��ȣȭ �� �迭�� �˻��ϴ� �Լ��� ����ϱ�� �����ߴ�. 
//�׸��� �� �˻簡 ����� �۵��ϴ��� �׽�Ʈ �� ���̴�.
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

}	// ��� : ���������� arrsize�� ���� �ι�� ����� ũ�⵵ �ι�� �� �Ҵ� �ϴ� ����� ���δ�. ����ü �� �Ҵ��� calloc�� �̷�� ���Ƿ�, file�� ������ ���������ε� ó���� �����ϴ�.
//�ٸ�, ������ �߰��ϴ� ���� ��ü�� ����ڰ� �ٷ�⿣ �����ϸ�, �����Լ��� �̿����� �ʱ⿡ ������ �� �ִ�. �̴� �����ڸ� �̿��Ͽ� �����ϰ� ���� �� ������ c������ �Ұ����ϴ�.

//���� ���� �� �Դ�. �� ����� ��� ũ�� ����� �Լ��� �ƴϹǷ�, �� ����� ���� ���� �̸��� ������ִ� ������ �켱 �׽�Ʈ�Ѵ�.
//�ش� �Լ��� ���� ����� ��ٷο���. ������ �������� �ڿ������� ���� �̸� �ڿ� ���� ���ڰ� ��������.
//�̸� char�� ó���ϱ⿣ ������ �ִ�. �ڸ����� ���ϴ� ������� �Ӹ� ������, �׷��� int�� �̿��� ���� ������ ����, ��ȣȭ/��ȣȭ�� �� �� ���� �̸��� ��� �Լ����� �Ѱ��ְ� �� ���̴�.
//�̸� �̿��Ͽ� ��ȣȭ/��ȣȭ �� "��ȣȭ_" "��ȣȭ_" ��Ʈ���� �̸� ������ �ΰ�, �� �ڿ� ���� ���� ������ �����ϴ� int ������ char ���·� ��ȯ��Ű�� strcat�� �̿��Ͽ� �ٿ��ش�.
//�ٸ�, itoa �Լ��� ���� visual studio ������ �ۿ� �۵����� �����Ƿ� �ٸ� ȯ�濡�� ����� �� ���� itoa �Լ��� ������ �ʿ䰡 �ִ�.
void test_6() {
	char name[] = "�׽�Ʈ_\0";
	int cnt = 1;

	char* Name = NULL;

	Name = makeFilename(name, cnt);
	if (Name == NULL) {
		printf("ũ�ƾ�\n");
		exit(1);
	}

	printf("%s", Name);
} //��� : ���� �� �̾� �ش�. ���߿� ����� �Լ��� �ٷ� ���� ���� ������ ����, ���ϸ� �ڿ� .txt�� �ٴ´�.


//����� �Լ��� �׽�Ʈ �� ���� �Դ�.
//�ϴ� �⺻������ ���� ��� ���̽��� ��������Ƿ�, �ٷ� ��ȣȭ / ��ȣȭ�� �����ϰڴ�.
//�����Ǵ� ���� ���̽��� �޸� �Ҵ� ����, ������ �Է�, ��ȣȭ�� �� ������ �޾��� �� ó��, �� ���� �� ���� �����ص� ��ټ��� ������ �����Ǿ���.
//�����ڵ� / ��ȣ�� �� ���� �� ��ȣȭ ����� �����Ͽ���.
void test_7() { //����Ǵ� ��� : ������Ʈ ���� test.txt�� �о ����� ����ϴ��� Ȯ�� �� ���̴�, ���� �б�/���Ⱑ ���� ���ٸ� ���� �׽�Ʈ�� ���� �׽�Ʈ�� �ȴ�.

	char* text = fileRead("test.txt");
	printf("%s\n", text);

	fileWrite("test_output.txt",text);

}	//��� : �ſ� �� ���´�.

//�Ѱ� �Լ����� toCiper, toPlain�� ���ʰ� �Դ�.
//�ִ��� ��� �и��� �ߴٰ� ���������� �׷��� �ڵ� ��ġ�� Ŀ���� �� ���� �Ƿ��� ������ ſ�� �� ���̱⿡�� �ð��� ������ �������� �ʾҴ�.
//�ƹ�ư, �� �Լ� ������ �����ٸ� ��ü �Լ����� �Է��� ������ �ʴ� �̻� ���׿� ���ܻ�Ȳ�� ���ٰ� �����ȴ�.
void test_8() {
	int fileCnt = 1;
	int arrsize = 2;
	int* pc = &fileCnt;
	int* ac = &arrsize;
	encryptionInfo* info = (encryptionInfo*)calloc(arrsize, sizeof(encryptionInfo));

	toCiper(info, &fileCnt, &arrsize);

	toPlain(info, &fileCnt, &arrsize);

	//��� : ��ġ�� ū ��ŭ �������� ���� ������ �־���, ���� ���� �Ƿ��� �̼��� ���� ũ�� ü���Ѵ�.
	//���ڿ��� textlen �κ��� �ε��� ��꿡 ������ �־ �����Ͽ���. toCiper�� �� ��� �Ϻ� ������ Ȯ���ߴ�.
	//toPlain�� �̸��� �о���� �� �ϴ� ������ �����ߴ�.
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