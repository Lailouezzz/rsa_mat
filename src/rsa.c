#include "rsa.h"


int rsa_init(void)
{
    struct timeb curtime;
    ftime(&curtime);
    srand(curtime.millitm);

    return 0;
}
