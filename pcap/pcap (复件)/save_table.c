void saveTable(attHead tmpH)
{
	FILE *fp;
        att pA,tmpA;
        reHead tmpR,pR;
        data tmpD,pD;
        int i=0;
        char dir[100];

        if(tmpH!=NULL)                                               //存表到相应文件
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
                        while(tmpR!=NULL)                               //校正记录数
                        {
                                ++i;
                                tmpR=tmpR->nextR;
                        }
                        tmpH->recordNum=i;

                        tmpR=tmpH->nextR;
                        fwrite(&tmpH->recordNum,sizeof(int),1,fp);      //写表头
                        fwrite(&tmpH->attributeNum,sizeof(int),1,fp);
                        for(i=0;i<tmpH->attributeNum;i++)
                        {
                                fwrite(tmpA,sizeof(struct attribute),1,fp);
                                tmpA=tmpA->nextA;
                        }
 			while(tmpR!=NULL)				//写数据
                        {
                                tmpD=tmpR->nextD;
                                tmpA = tmpH->nextA;

                                while(tmpD!=NULL)
                                {
                                        if(strcmp(tmpA->attributeType,"int") == 0) fwrite(&tmpD->dataInt,sizeof(long long int),1,fp);
                                        else
                                        {
                                                fputs(tmpD->dataChar,fp);
                                                fputc('\n',fp);
                                        }
                                        tmpD=tmpD->nextD;
                                        tmpA = tmpA->nextA;
                                }
                                tmpR=tmpR->nextR;
                        }
			fclose(fp);
                }
        }

}
