#include"head.h"

void quit(struct attributeHead *head)
{
	FILE *fp;
	struct attributeHead *pH,*tmpH;
	struct attribute *pA,*tmpA;
	struct recordHead *tmpR,*pR;
	struct data *tmpD,*pD;
	int i=0;
	char dir[100];


	tmpH=head->nextH;
	while(tmpH!=NULL)						//存表到相应文件
	{
		getcwd(dir,100);                                       //读当前路径，并设置读取文件路径为当前目录的/data文件夹下
		strcat(dir,"/data/");
		strcat(dir,tmpH->tableName);

		if((fp=fopen(dir,"wb+"))==NULL)
		{
			printf("error!");
		}
		else
		{
			tmpA=tmpH->nextA;
			tmpR=tmpH->nextR;

			rewind(fp);
			
			i=0;
			while(tmpR!=NULL)				//校正记录数
			{
				++i;
				tmpR=tmpR->nextR;
			}
			tmpH->recordNum=i;

			tmpR=tmpH->nextR;
			fwrite(&tmpH->recordNum,sizeof(int),1,fp);	//写表头
			fwrite(&tmpH->attributeNum,sizeof(int),1,fp);
			for(i=0;i<tmpH->attributeNum;i++)
			{
				fwrite(tmpA,sizeof(struct attribute),1,fp);
				tmpA=tmpA->nextA;
			}

			while(tmpR!=NULL)
			{
				tmpD=tmpR->nextD;

				while(tmpD!=NULL)
				{
					if(tmpD->dataChar==NULL) fwrite(&tmpD->dataInt,sizeof(long long int),1,fp);
					else
					{
						fputs(tmpD->dataChar,fp);
						fputc('\n',fp);
					}
					tmpD=tmpD->nextD;
				}
				tmpR=tmpR->nextR;
			}
			saveIndex(tmpH);
		}
		tmpH=tmpH->nextH;
	}

	
	tmpH=head->nextH;								//释放分配内存
	free(head);
	while(tmpH!=NULL)
	{
	//	freeIndex(tmpH);
		pH=tmpH->nextH;
		tmpA=tmpH->nextA;
		tmpR=tmpH->nextR;
		free(tmpH);
		while(tmpA!=NULL)
		{
			pA=tmpA->nextA;
			free(tmpA);
			tmpA=pA;
		}
		while(tmpR!=NULL)
		{
			pR=tmpR->nextR;
			tmpD=tmpR->nextD;
			free(tmpR);
			while(tmpD!=NULL)
			{
				pD=tmpD->nextD;
				free(tmpD->dataChar);
				free(tmpD);
				tmpD=pD;
			}
			tmpR=pR;
		}
		tmpH=pH;
	}
}
