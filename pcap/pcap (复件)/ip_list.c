//#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
typedef struct _ip_oicq{
    char *sip;
    char *dip;
    struct _ip_oicq *next;
}*ip_oicq,ip_oicq_node;
/*
ip_oicq init_ip_list(ip_oicq head);
void insert_ip_list(ip_oicq head,char sip[],char dip[]);
int search_ip_list(ip_oicq head,char sip[],char dip[]);
void delete_ip_list(ip_oicq head,int num);
void display_ip_list(ip_oicq head);

void main(){
    ip_oicq head,p;
    head = init_ip_list(head);
    insert_ip_list(head,"123.123.456.567","255.255.255.0");
    insert_ip_list(head,"123.123.456.567","123.123.11.11");
    insert_ip_list(head,"123.123.456.567","123.23.110.23");
    insert_ip_list(head,"123.123.456.567","123.123.123.0");
    display_ip_list(head);
    printf("%d\n",search_ip_list(head,"205.255.255.0","123.123.456.567"));
    delete_ip_list(head,3);
    display_ip_list(head);

}
*/
ip_oicq init_ip_list(ip_oicq head){
    head = (ip_oicq)malloc(sizeof(ip_oicq_node));
    if(head){
	head->next = NULL;
       	return head;
    }
    return NULL;
}

void insert_ip_list(ip_oicq head,char sip[],char dip[]){
    ip_oicq tmp,q;
    tmp = (ip_oicq)malloc(sizeof(ip_oicq_node));
    if(tmp){
	tmp->sip = (char *)malloc(16*sizeof(char));
	tmp->dip = (char *)malloc(16*sizeof(char));
	strcpy(tmp->sip,sip);
	strcpy(tmp->dip,dip);
	q = head;
	while(q->next){
	    q = q->next;
	}
	tmp->next = q->next;
	q->next = tmp;
    }
}

int search_ip_list(ip_oicq head,char srcip[],char desip[]){
    ip_oicq tmp;
    int flag = 0;
    tmp = head->next;
    while(tmp){
	if(strcmp(tmp->sip,srcip) == 0 && strcmp(tmp->dip,desip) ==0){
	    flag = 1;
	    break;
	}
	if(strcmp(tmp->sip,desip) == 0 && strcmp(tmp->dip,srcip) == 0){
	    flag = 1;
	    break;
	}
	tmp = tmp->next;
    }
    return flag;
}

void delete_ip_list(ip_oicq head,int num){
    ip_oicq tmp;
    int len = 0;
    tmp = head->next;
    while(tmp){
	len++;
	tmp = tmp->next;
    }
    if(num > len)
	num = len;
    while(num != 0){
	tmp = head->next;
    	head->next = head->next->next;
    	free(tmp->sip);
    	free(tmp->dip);
	free(tmp);
	num--;
    }
}

void display_ip_list(ip_oicq head){
    ip_oicq p;
    p = head->next;
    while(p){
	printf("%s\n",p->sip);
	printf("%s\n",p->dip);
	p = p->next;
    }
}

void free_ip_list(ip_oicq head){
    ip_oicq p,q;
    p = head->next;
    while(p){
	q = p;
	p = p->next;
	free(q->sip);
	free(q->dip);
	free(q);
    }
    free(head);
}
