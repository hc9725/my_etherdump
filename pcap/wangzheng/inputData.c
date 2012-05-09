#include"head.h"

void inputData(struct attributeHead *head)
{
	struct attributeHead *pH,*tmpH;
	struct attribute *pA,*tmpA;
	struct recordHead *tmpR;
	struct data *tmpD,*pD;

	char name[50],key='y',dir[100];
	int i;	

	printf("请输入要插入数据的表名：");
	fgets(name,50,stdin);                                   //gets()可能造成缓冲区溢出，故用fgets
	name[strlen(name)-1]='\0';                              //fgets()读取的字符串以'\n'结尾；一般字符串以'\0'结尾；将'\n'转化成'\0'；否则比较字符串会出错

	tmpH=findTable(head,name);

	if(tmpH!=NULL)
	{
		while(key!='n' && key!='N')
		{
			tmpR=(struct recordHead *)malloc(sizeof(struct recordHead));
		  	tmpR->nextD=NULL;
		  	tmpR->nextR=NULL;
			tmpR->preR=NULL;
			tmpR->offset=tmpH->recordNum;
			
			pA=tmpH->nextA;
			printf("请输入数据：\n");
			while(pA!=NULL)				//分配一个Record的存储空间 形成链表结构
			{	
				tmpD=(struct data *)malloc(sizeof(struct data));
				tmpD->nextD=NULL;
				printf("属性：%s  数据类型：%s  字节数：%d\n",pA->attributeName,pA->attributeType,pA->attributeSize);
				if(strcmp(pA->attributeType,"char")==0)
				{
					tmpD->dataChar=(char *)malloc(pA->attributeSize+1);
					fgets(tmpD->dataChar,pA->attributeSize+1,stdin);
					tmpD->dataChar[strlen(tmpD->dataChar)-1]='\0';
				}
				if(strcmp(pA->attributeType,"int")==0)
				{
					tmpD->dataChar=NULL;
					scanf("%lld",&tmpD->dataInt);
					getchar();
				}

				if(tmpR->nextD==NULL)	tmpR->nextD=tmpD;
				else pD->nextD=tmpD;
				pD=tmpD;
				pA=pA->nextA;
			}
			insertRecord(tmpH,tmpR);
			insertIndex(tmpH,tmpR);

			printf("按任意建继续输入，按N退出...\n");
			key=getkey();
		}
	}
}

