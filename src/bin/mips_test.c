#include<stdio.h>
#include <stdlib.h>

char* next(char* y)
{
    *y='i';
    *(y+1)='d';
    return y;
}
int main()
{
    char* a;
    char* y=(char*)malloc(10);
    a = next(y);
    system(a);
    return 0;
}
