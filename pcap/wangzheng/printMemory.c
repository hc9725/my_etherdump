#include"head.h"

void printMemory(struct attributeHead *head)
{
	struct attributeHead *tmpH,*pH;
	struct recordHead *tmpR , *pR;
	struct data *tmpD , *pD;
	struct attribute *pA,*tmpA;
//	struct indexHead *tmpIH,*pIH;
//	struct indexRecord *tmpIR,*pIR;
//	struct indexData *tmpID,*pID;
//	struct indexData_Char *tmpID_C,*pID_C;
	int i, j;

	tmpH=head->nextH;
	if(tmpH==NULL)
		printf("内存中无数据！\n");

	while(tmpH!=NULL)
	{
		printf("表名：%s\n",tmpH->tableName);
		printf("属性数：%d\n",tmpH->attributeNum);
		printf("记录数：%d\n",tmpH->recordNum);
		printf("偏移量     ");
		tmpA=tmpH->nextA;
		while(tmpA!=NULL)
		{
			printf("%10s(%-4s)\t",tmpA->attributeName,tmpA->attributeType);
			tmpA=tmpA->nextA;
		}
		printf("\n");
		
		tmpR=tmpH->nextR;
		while(tmpR!=NULL)
		{
			printf("%9d",tmpR->offset);
			tmpD=tmpR->nextD;
			while(tmpD!=NULL)
			{
				if(tmpD->dataChar==NULL) printf("%14lld\t\t",tmpD->dataInt);
				if(tmpD->dataChar!=NULL) printf("%14s\t\t",tmpD->dataChar);
				tmpD=tmpD->nextD;
			}
			printf("\n");
			tmpR=tmpR->nextR;
		}
		printf("\n");
		
		tmpIH=tmpH->nextI;
		if(tmpH->nextI==NULL)	printf("head->nextI==NULL\n");
		while(tmpIH!=NULL)
		{
			printf("索引名：%s\n",tmpIH->name);
			tmpIR=tmpIH->nextR;
			if(strcmp(tmpIH->type,"int")==0)
			{
				for(i=0;i<1024;i++)
				{
					tmpID=tmpIR[i].nextI;
					if(tmpID!=NULL)
					{
						printf("桶号：%d\n",i);
					}
					while(tmpID!=NULL)
					{
						printf("%lld %d %d\n",tmpID->dataInt,tmpID->offset,tmpID->pR);
						tmpID=tmpID->nextI;
					}
				}
			}
			if(strcmp(tmpIH->type,"char")==0)
			{
				for(i=0;i<65536;i++)
				{
					tmpID=tmpIR[i].nextI;
					if(tmpID!=NULL)
					{
						printf("桶号：%d\n",i);
					}
					while(tmpID!=NULL)
					{
						printf("%s %d %d\n",tmpID->dataChar,tmpID->offset,tmpID->pR);
						tmpID=tmpID->nextI;
					}
				}
					 
			}
			tmpIH=tmpIH->nextH;
		}

		tmpH=tmpH->nextH;
	}

}


