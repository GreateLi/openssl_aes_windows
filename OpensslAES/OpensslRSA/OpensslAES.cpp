// OpensslRSA.cpp : 定义控制台应用程序的入口点。
//

 
#include <stdio.h>
 
#include <stdlib.h>
#include <tchar.h>
#include "utils_openssl.h"
 
 
#include <openssl/aes.h>
char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n";


//把字符串写成public.pem文件
int createPublicFile(char *file, const string &pubstr)
{
	if (pubstr.empty())
	{
		printf("public key read error\n");
		return (-1);
	}
	int len = pubstr.length();
	string tmp = pubstr;
	for (int i = 64; i<len; i += 64)
	{
		if (tmp[i] != '\n')
		{
			tmp.insert(i, "\n");
		}
		i++;
	}
	tmp.insert(0, "-----BEGIN PUBLIC KEY-----\n");
	tmp.append("\n-----END PUBLIC KEY-----\n");

	//写文件
	ofstream fout(file);
	fout << tmp;

	return (0);
}

//把字符串写成private.pem文件
int createPrivateFile(char *file, const string &pristr)
{
	if (pristr.empty())
	{
		printf("public key read error\n");
		return (-1);
	}
	int len = pristr.length();
	string tmp = pristr;
	for (int i = 64; i<len; i += 64)
	{
		if (tmp[i] != '\n')
		{
			tmp.insert(i, "\n");
		}
		i++;
	}
	tmp.insert(0, "-----BEGIN RSA PRIVATE KEY-----\n");
	tmp.append("-----END RSA PRIVATE KEY-----\n");

	//写文件
	ofstream fout(file);
	fout << tmp;

	return (0);
}
bool  writeFile(const char * path, const char * data)
{
	FILE *fp;
	if ((fp = fopen(path, "wb")) == NULL)
	{
		LOGE("file cannot open %s", path);
		return false;
	}
	else
	{
		fwrite(data, 1, strlen(data), fp);
	}
	if (fclose(fp) != 0)
	{
		LOGD("file cannot be closed \n");
	}
	else
	{
		LOGD("file is now closed \n");
	}

	return true;
}
void  Bytes2HexStr(unsigned char *src, int srcLen, unsigned char *des)
{
	unsigned char *res;
	int i = 0;

	res = des;
	while (srcLen>0)
	{
		sprintf((char*)(res + i * 2), "%02x", *(src + i));
		i++;
		srcLen--;
	}
}
long long  getCurrentMillisecondCount()
{
 
	struct timeval tp;

	time_t clock;
	struct tm tm;
	SYSTEMTIME wtm;
	GetLocalTime(&wtm);
	tm.tm_year = wtm.wYear - 1900;
	tm.tm_mon = wtm.wMonth - 1;
	tm.tm_mday = wtm.wDay;
	tm.tm_hour = wtm.wHour;
	tm.tm_min = wtm.wMinute;
	tm.tm_sec = wtm.wSecond;
	tm.tm_isdst = -1;
	clock = mktime(&tm);
	tp.tv_sec = clock;
	tp.tv_usec = wtm.wMilliseconds;
	return (long long)tp.tv_sec * 1000 + tp.tv_usec;

 
}
int  aes_decrypt(const unsigned char* in, const unsigned char* key, unsigned char* out, int inLen)
{
	if (!in || !key || !out) return 0;
	//unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
	//for (int i = 0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
	//	iv[i] = 0;
	unsigned char iv[] = "0000000000000000";//{ 0 };//加密的初始化向量
	AES_KEY aes;
	int bitslen = strlen((char*)key) * 8;
	//edit ligq20180624
	// if (AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
	if (AES_set_decrypt_key((unsigned char*)key, bitslen, &aes) < 0)
	{
		return 0;
	}
	int len = inLen;
	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
	return 1;
}

void aes_cbc_pcsk5_encrypt(const unsigned char* pcInput, unsigned char* key,int nLen, unsigned char* pcOut)
{
	
	unsigned char iv[ ] = "0000000000000000";//{ 0 };//加密的初始化向量
	//for (int i = 0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
	//	iv[i] = 0;
	//unsigned char *pIV = &iv;
	 
	unsigned char encrypt_string[1024] = { 0 };
	AES_KEY aes;
	int n = 0;

	int nBei = nLen / AES_BLOCK_SIZE + 1;
	int nTotal = nBei * AES_BLOCK_SIZE;
	unsigned char *enc_s = (unsigned char*)malloc(nTotal);
	int nNumber = 0;
	printf("nBei=%d, nTotal=%d,nLen=%d\n", nBei, nTotal, nLen);

	//KCS5Padding：填充的原则是,如果长度少于16个字节，需要补满16个字节，补(16-len)个(16-len)例如：
	//"31325980"这个节符串是8个字节，16-8=8,补满后如：31325980+8个十进制的8
	//如果字符串长度正好是16字节，则需要再补16个字节的十进制的16。
	if (nLen % 16 > 0)
	{
		nNumber = nTotal - nLen;
		printf("number=%d\n", nNumber);
	}
	else
	{
		nNumber = 16;
	}

	memset(enc_s, nNumber, nTotal);
	memcpy(enc_s, pcInput, nLen);
	printf("enc_s=%s\n", enc_s);

	//设置加密密钥，16字节
	int keyLen = strlen((char*)(key)) * 8;
	if (AES_set_encrypt_key((unsigned char*)key, keyLen, &aes) < 0)
	{
		fprintf(stderr, "Unable to set encryption key in AES\n");
		exit(-1);
	}

	AES_cbc_encrypt((unsigned char *)enc_s, pcOut, nTotal, &aes, (unsigned char*)iv, AES_ENCRYPT);
 
	int colorEnLen = nLen + 16 - nLen % 16;
	printf("encrypt_string n:%d, %ld\n", n, sizeof(encrypt_string));
	Bytes2HexStr((unsigned char*)pcOut , colorEnLen, (unsigned char*)encrypt_string);
	//base64_encode(encrypt_string, nTotal, pcOut);


	///n = strlen(pcOut);
	printf("out  :%s\n", encrypt_string);

 	free(enc_s);
}

int main()
{
	unsigned char   key[] = "8rrh1086omGe8qF0jgvxM53tASc46YHa";
//	memcpy(key, "8rrh1086omGe8qF0jgvxM53tASc46YHa", 32);
 
	 unsigned char encrypt_string[4096] = { 0 };
	 AES_KEY aes;

	// char iv[17] = "0000000000000000";

	// std::string input_string = "nihaowoshililei";
	 const unsigned char inputString[27] = "nihaowoshililei1";
	 int inLen = strlen((char*)inputString);
	 aes_cbc_pcsk5_encrypt(inputString, key, inLen,encrypt_string);
	 int enLen = inLen + 16 - inLen % 16;
	 unsigned  char * debuf = new unsigned char[inLen];

	 aes_decrypt((const unsigned char*)encrypt_string, key, debuf,enLen);
	 char deString[1024] = { 0 };
	 memcpy(deString, debuf, inLen);
	 printf("\ndebuf:%s\n", deString);

    return 0;
}

