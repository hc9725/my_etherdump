#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<termios.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<fcntl.h>
#define bucketSize_Int 1024
#define bucketSize_Char 65536

struct attribute
{
	char attributeName[50];
	char attributeType[10];
	int  attributeSize;
	struct attribute *nextA;
};

struct attributeHead				//表头
{
	char tableName[50];
	int attributeNum;			//属性数
	int recordNum;				//记录数
	struct attribute *nextA;		//下一个属性
        struct recordHead *nextR;		//下一条记录
	struct attributeHead *nextH;		//下一个表
	struct indexHead *nextI;		//下一条索引
};

struct data					//表的数据
{
	long long int dataInt;			//存储64位长整型
	char *dataChar;				//存储字符串
	struct data *nextD;
};

struct recordHead
{
	int offset;			//记录的偏移地址，第一条为0
	struct data *nextD;		//记录的第一字段
	struct recordHead *nextR;	//下一条记录
	struct recordHead *preR;	//上一条记录
};

struct findData
{
	int findPlace;			//查找的字段号
	char findName[50];		//查找的字段属性
	long long int findInt;
	char *findChar;
	struct findData *nextF;
};

struct findResultHead			//查找结果链表头
{
	struct attributeHead *pH;
	struct findResult *nextF;
};

struct findResult
{
	struct recordHead *pR;
	struct findResult *nextF;
};

struct indexData
{
	long long int dataInt;
	char *dataChar;
	int offset;
	int *pOffset;
	struct recordHead *pR;
	struct indexData *nextI;
	struct indexData *preI;
};

struct indexHead
{
	char name[50];
	char type[10];
	struct indexRecord *nextR;
	struct indexHead *nextH;
};

struct indexRecord
{
	struct indexData *nextI;
};

void creatTable(struct attributeHead *);
char getkey();
void inputData(struct attributeHead *);
int readTableHead(struct attributeHead * , char *);
int readTable(struct attributeHead * , char *);
void readTest2(struct attributeHead *);
void quit(struct attributeHead *);
void printMemory(struct attributeHead *);
void insertRecord(struct attributeHead * , struct recordHead *);
void deleteRecord(struct attributeHead *);
void deleteTable(struct attributeHead *);
void creatIndex(struct attributeHead *, int);
void readIndex(struct attributeHead *,char *);
void insertIndex(struct attributeHead * , struct recordHead *);
int BKDRHash(char *);
void saveIndex(struct attributeHead *);
void freeIndex(struct attributeHead *);
void deleteIndex(char *);
void find(struct attributeHead *);
void findRecord(struct attributeHead * , struct findData * , struct findResultHead *);
struct attributeHead *findTable(struct attributeHead *,char *);
void inputConditions(struct attributeHead * , struct findData *);
void deleteIndexRecord(struct attributeHead * , struct recordHead *);
void newIndex(struct attributeHead *);
