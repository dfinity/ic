/* 

C implementation of some standard libraries that Csmith might include in a randomly generated C code

 */

void * memcpy(void* dst, const void* src, unsigned int cnt)
{
  char *pszDest = (char *)dst;

  const char *pszSource =( const char*)src;

  while(cnt) //till cnt
    {
      //Copy byte by byte
      *(pszDest++)= *(pszSource++);
      --cnt;
    }

  return dst;
}


void * memset(void *s, int c,  unsigned int len)
{
    unsigned char* p=s;
    while(len--)
    {
        *p++ = (unsigned char)c;
    }
    return s;
}

int printf (const char *buff, ...) {
}
