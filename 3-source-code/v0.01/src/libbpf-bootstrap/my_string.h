#ifndef MY_STRING_H
#define MY_STRING_H

#define statfunc static __always_inline
//my_bpf_strncmp等价于bpf_strncmp帮助函数，重新实现它是因为bpf_strncmp仅在较新的内核版本中支持。

//PROTOTYPES
statfunc int strncmp(const char *cs, const char *ct, size_t count);
statfunc int my_bpf_strncmp(const char * s1, u32 s1_sz, const char * s2);
//FUNCS
//bpf_strncmp的替代品
statfunc int strncmp(const char *cs, const char *ct, size_t count)
{
	unsigned char c1, c2;

	while (count) {
		c1 = *cs++;
		c2 = *ct++;
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1)
			break;
		count--;
	}
	return 0;
}


statfunc int my_bpf_strncmp(const char * s1, u32 s1_sz, const char * s2)
{
	return strncmp(s1, s2, s1_sz);
}

#endif
