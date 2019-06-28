# openssl_aes_windows
openssl aes windows JAVA  AES/CBC/PKCS5Padding  ; C++ AES_CBC_PKCS5Padding 
首先对齐的 格式：JAVA  AES/CBC/PKCS5Padding  ; C++ AES_CBC_PKCS5Padding

 

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);

参数说明：
参数名称 	描述
userKey 	用户指定的密码。注意：只能是16、24、32字节。如果密码字符串长度不够，可以在字符串末尾追加一些特定的字符，或者重复密码字符串，直到满足最少的长度。
bits 	密码位数。即userKey的长度 * 8，只能是128、192、256位。
key 	向外输出参数。

一、首先是公钥必须是和服务端私钥是一对；

二、填充方式必须一致；

这里说一下C++  必须是 PKCS5Padding填充；

void aes_cbc_pcsk5_encrypt(char* pcInput, int nLen, char* pcOut)
{
	unsigned char key[33] = "8rrh1086omGe8qF0jgvxM53tASc46YHa";
	unsigned char iv[AES_BLOCK_SIZE] = { 0 };//加密的初始化向量
	for (int i = 0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
		iv[i] = 0;
	strcpy((char*)iv, "0000000000000000");
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

	AES_cbc_encrypt((unsigned char *)enc_s, (unsigned char*)encrypt_string, nTotal, &aes, (unsigned char*)iv, AES_ENCRYPT);
	n = strlen((char*)encrypt_string);
	//bool mColorRet = 0 < nLen % 16;
	int colorEnLen = nLen + 16 - nLen % 16;
	printf("encrypt_string n:%d, %ld\n", n, sizeof(encrypt_string));
	Bytes2HexStr((unsigned char*)encrypt_string, colorEnLen, (unsigned char*)pcOut);
	//base64_encode(encrypt_string, nTotal, pcOut);


	n = strlen(pcOut);
	printf("n:%d  :%s\n", n,pcOut);
        free(enc_s );
}
 

三、还要注意一下，上面代码中的IV，内容也必须一致；

四、还有一点需要注意 usrkey 长度 这个是key乘8 以不是固定值，（一般有三种可选 128，192，256）实际长度 和key相关；

    //设置加密密钥，16字节
    int keyLen = strlen((char*)(key)) * 8;
    if (AES_set_encrypt_key((unsigned char*)key, keyLen, &aes) < 0)

五、最后，加密码后没有给出加密长度，这个需要自己算一下。

void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const AES_KEY *key,
                     unsigned char *ivec, const int enc);

参数说明：
参数名称 	描述
in 	输入数据。长度任意。
out 	输出数据。能够容纳下输入数据，且长度必须是16字节的倍数。
length 	输入数据的实际长度。
key 	使用AES_set_encrypt/decrypt_key生成的Key。
ivec 	可读写的一块内存。长度必须是16字节。
enc 	是否是加密操作。AES_ENCRYPT表示加密，AES_DECRYPT表示解密。

这个没有加密后长度，输出长度和输入长度密码相关，可以根据输入长度算出。

例 nLen =22; 为输入长度；哪么输出长度为：

int colorEnLen = nLen + 16 - nLen % 16;

 
