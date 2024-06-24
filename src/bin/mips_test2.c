#include<stdio.h>
#include <string.h>

int main()
{
    char a[100];
    scanf("%s",a);

    int m=111;
    int n=222;

    sprintf(a, "m:%d,n:%d,l:%d\n",m,*a,n);
    
    
    system(a);
    
    return 0;
}
