//将抓到的数据包存储到链表中
typedef struct attribute        //表的属性
{
	char attributeName[50];
	char attributeType[10];
	int  attributeSize;
	struct attribute *nextA;
}*att;

typedef struct attributeHead				//表头
{
	char tableName[50];
	int attributeNum;			//属性数
	int recordNum;				//记录数
	struct attribute *nextA;		//下一个属性
        struct recordHead *nextR;		//下一条记录
	struct attributeHead *nextH;		//下一个表
	struct indexHead *nextI;		//下一条索引
}*attHead;

typedef struct _data					//表的数据
{
	long long int dataInt;			//存储64位长整型
	char *dataChar;				//存储字符串
	struct _data *nextD;
}*data;

typedef struct recordHead
{
	int offset;			//记录的偏移地址，第一条为0
	struct _data *nextD;		//记录的第一字段
	struct recordHead *nextR;	//下一条记录
	struct recordHead *preR;	//上一条记录
}*reHead;

//初始化表头
attHead init_attHead(){
    attHead tmp;
    att tmp1,tmp2,tmp3,tmp4;
    tmp = (attHead)malloc(sizeof(struct attributeHead));
    if(tmp){
	strcpy(tmp->tableName,"test");
	tmp->attributeNum = 4;
	tmp->recordNum = 0;
	tmp1 = (att)malloc(sizeof(struct attribute));
	if(tmp1){
	    strcpy(tmp1->attributeName,"number");
	    strcpy(tmp1->attributeType,"int");
	    tmp1->attributeSize = 8;
	    tmp->nextA = tmp1;
	    tmp2 = (att)malloc(sizeof(struct attribute));
	    if(tmp2){
		strcpy(tmp2->attributeName,"source ip");
		strcpy(tmp2->attributeType,"char");
		tmp2->attributeSize = 50;
		tmp1->nextA = tmp2;
		tmp3 = (att)malloc(sizeof(struct attribute));
		if(tmp3){
		    strcpy(tmp3->attributeName, "destination ip");
		    strcpy(tmp3->attributeType,"char");
		    tmp3->attributeSize = 50;
		    tmp2->nextA = tmp3;
		    tmp4 = (att)malloc(sizeof(struct attribute));
		    if(tmp4){
		    strcpy(tmp4->attributeName,"protocol type");
		    strcpy(tmp4->attributeType,"char");			
			tmp4->attributeSize = 50;
			tmp3->nextA = tmp4;
			tmp4->nextA = NULL;
		    }
		}
	    }
	}
	tmp->nextR = NULL;
	tmp->nextH = NULL;
	tmp->nextI = NULL;
    }
    return tmp;
}

//打印表头和表的数据部分
void printMemory(attHead head){
    attHead tmpH,pH;
    reHead tmpR , pR;
    data tmpD , pD;
    att pA,tmpA;
    int i, j;

    tmpH = head;
    if(tmpH==NULL)
	printf("内存中无数据！\n");
    while(tmpH!=NULL){
	printf("表名：%s\n",tmpH->tableName);
	printf("属性数：%d\n",tmpH->attributeNum);
	printf("记录数：%d\n",tmpH->recordNum);
	printf("偏移量     ");
	tmpA=tmpH->nextA;
	while(tmpA!=NULL){
	    printf("%10s(%-4s)\t",tmpA->attributeName,tmpA->attributeType);
	    tmpA=tmpA->nextA;
	}
	printf("\n");
	tmpR=tmpH->nextR;
	while(tmpR!=NULL){
	    printf("%9d",tmpR->offset);
	    tmpD=tmpR->nextD;
	    while(tmpD!=NULL){
		if(tmpD->dataChar==NULL) printf("%14lld\t\t",tmpD->dataInt);		
		if(tmpD->dataChar!=NULL) printf("%14s\t\t",tmpD->dataChar);			
		tmpD=tmpD->nextD;
	    }
	    printf("\n");								
    	    tmpR=tmpR->nextR;						
	}				
	printf("\n");							
	tmpH=tmpH->nextH;
    }
}

//插入记录
void insertRecord(attHead tmpH , reHead tmpR){
    	reHead pR;
	pR=tmpH->nextR;
	if(tmpH->nextR==NULL)   
	    tmpH->nextR=tmpR;
	else{
	    while(pR->nextR!=NULL)
		pR=pR->nextR;
	    pR->nextR=tmpR;
	    tmpR->preR=pR;
	}	
	tmpR->offset = tmpH->recordNum;
	tmpH->recordNum++;
}

//插入数据部分
void insert_data(attHead att_head,int count,char ch[],char srcip[],char desip[]){
//    pro_list tmp;
    reHead record;
    data data1,data2,data3,data4;
//    tmp = proto->next;
//    while(tmp){
       	record = (reHead)malloc(sizeof(struct recordHead));
	record->nextR = NULL;
	record->preR = NULL;
       	data1 = (data)malloc(sizeof(struct _data));
    	if(data1){
    	    data1->dataInt = count;
    	    data1->dataChar = NULL;
    	    record->nextD = data1;
    	    data2 = (data)malloc(sizeof(struct _data));
    	    if(data2){
		data2->dataChar = (char *)malloc(50*sizeof(char));
    		strcpy(data2->dataChar,srcip);
		data1->nextD = data2;
    		data3 = (data)malloc(sizeof(struct _data));
    		if(data3){
		    data3->dataChar = (char *)malloc(50*sizeof(char));
    		    strcpy(data3->dataChar,desip);
		    data2->nextD = data3;
		    data4 = (data)malloc(sizeof(struct _data));
		    if(data4){
			data4->dataChar = (char *)malloc(50*sizeof(char));
			strcpy(data4->dataChar,ch);
			data3->nextD = data4;
			data4->nextD = NULL;
		    }
    		}
    	    }
	}
  //  }
    insertRecord(att_head,record);
//    tmp = tmp->next;
}

//释放表头和数据
void free_data(attHead att_head){
    attHead tmpH,pH;
    att pA,tmpA;
    reHead pR,tmpR;
    data tmpD,pD;
    tmpH = att_head;
    while(tmpH){
	pH = tmpH->nextH;
	tmpA = tmpH->nextA;
	tmpR = tmpH->nextR;
	free(tmpH);
	while(tmpA){
	    pA=tmpA->nextA;
	    free(tmpA);
	    tmpA=pA;
	}
	while(tmpR){
	    pR=tmpR->nextR;
	    tmpD=tmpR->nextD;
	    free(tmpR);
	    while(tmpD!=NULL){	
		pD=tmpD->nextD;						
		free(tmpD->dataChar);				
		free(tmpD);
		tmpD=pD;
	    }
	    tmpR=pR;
	}
	tmpH = pH;
    }
}
