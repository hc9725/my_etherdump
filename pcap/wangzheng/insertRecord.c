#include"head.h"

void insertRecord(struct attributeHead *tmpH , struct recordHead *tmpR)
{
	struct recordHead *pR;

	pR=tmpH->nextR;
/*	if(pR!=NULL)
	{
		while(pR->nextR!=NULL)
			pR=pR->nextR;
	}
*/
	if(tmpH->nextR==NULL)   tmpH->nextR=tmpR;
	else    
	{
                while(pR->nextR!=NULL)
                        pR=pR->nextR;

		pR->nextR=tmpR;
		tmpR->preR=pR;
	}

	tmpH->recordNum++;
}
