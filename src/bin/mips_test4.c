#include<stdio.h>
#include<stdlib.h>


void producestr(char* a)
{
    *a = 'd';
    *(a+1) = 'i';
    *(a+2) = 'r';
}


int main()
{
    char a[]="aaa";
    producestr(a);
    printf("%s",a);
    system(a);
    return 0;
}
