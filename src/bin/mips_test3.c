#include<stdio.h>
#include <string.h>
void vul2()
{
    system("dir");
}

void vul(char* a,char* b)
{
    system(b);
}


void next(char* a)
{
    if(*a==1)
    {
        vul(a,"a");
        system(a);
    }else if(*a==2)
    {
        vul(a,"b");
        system(a);
    }
}


int main()
{
    char a[100];
    scanf("%s",a);

    int m=111;
    int n=222;
    int l=333;
    sprintf(a, "m:%d,n:%d,l:%d\n",m,n,l);
    
    
    char src[40];

    memset(src, 0, sizeof(src));
    strcpy(src, "test string");

    vul2();
    
    if(*a==1)
    {
        next(a);
    }else if(*a==2)
    {
        next(a);
    }else if(*a==3)
    {
        next(a);
    }
    
    return 0;
}
