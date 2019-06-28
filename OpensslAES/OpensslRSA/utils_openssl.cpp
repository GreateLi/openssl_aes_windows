
#include "utils_openssl.h"
int padding = RSA_PKCS1_PADDING;
#if  defined(WIN32) || defined(_WIN32) || defined(WINDOWS)
 
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
 
#if defined(LIB)
#pragma comment(lib, "ImiNect.lib")
#endif
#define  PLATFORM "windows"
#elif  defined(LINUX)
 
#include <dlfcn.h>
#define  PLATFORM "linux"
#else
 
#define  PLATFORM "android"
#include <dlfcn.h>
#endif
  string utils_openssl::formatPublicKey(string Key)
{
    string tmpKey = Key;
    int nPublicKeyLen = tmpKey.size(); //strPublicKey为base64编码的公钥字符串
    for(int i = 64; i < nPublicKeyLen; i+=64)
    {
        if(tmpKey[i] != '\n'){tmpKey.insert(i, "\n");}i++;
    }
    tmpKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
    tmpKey.append("\n-----END PUBLIC KEY-----\n");
    return tmpKey;
}

  RSA* utils_openssl::createRSA(unsigned char* key, int flag)
{
    RSA *rsa= NULL;
    BIO *keybio=NULL;
    keybio = BIO_new_mem_buf(key, -1);

    if (keybio==NULL) {
        LOGD( "Failed to create key BIO");
        return 0;
    }

    if(flag)
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
    else
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

    if(rsa == NULL)
        LOGD( "Failed to create RSA");

    return rsa;
}

//产生长度为length的随机字符串
  char* utils_openssl::genRandomString(int length)
{
    int flag, i;
    char* string;
    srand((unsigned) time(NULL ));
    if ((string = (char*) malloc(length)) == NULL )
    {
        LOGD("Malloc failed!flag:14\n");
        return NULL ;
    }

    for (i = 0; i < length - 1; i++)
    {
        flag = rand() % 3;
        switch (flag)
        {
            case 0:
                string[i] = 'A' + rand() % 26;
                break;
            case 1:
                string[i] = 'a' + rand() % 26;
                break;
            case 2:
                string[i] = '0' + rand() % 10;
                break;
            default:
                string[i] = 'x';
                break;
        }
    }
    string[length - 1] = '\0';
    return string;
}
  //私钥签名，公钥验签
  int utils_openssl::private_sign(const unsigned char *in_str, unsigned int in_str_len, unsigned char *outret, unsigned int *outlen, unsigned char*key)
  {
	  RSA* rsa = createRSA(key, 0);
	  int result = RSA_sign(NID_sha1, in_str, in_str_len, outret, outlen, rsa);
	  if (result != 1)
	  {
		  printf("sign error\n");
		  return -1;
	  }
	  return result;
  }
  int utils_openssl::public_verify(const unsigned char *in_str, unsigned int in_len, unsigned char *outret, unsigned int outlen, unsigned char*key)
  {
	  RSA* rsa = createRSA(key, 1);
	  int result = RSA_verify(NID_sha1, in_str, in_len, outret, outlen, rsa);
	  if (result != 1)
	  {
		  printf("verify error\n");
		  return -1;
	  }
	  return result;
  }
  //公钥加密，私钥解密
  int utils_openssl::public_encrypt(unsigned char*data, int data_len, unsigned char*key, unsigned char*encrypted)
  {
	  RSA* rsa = createRSA(key, 1);
	  int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
	  return result;
  }

  int utils_openssl::private_decrypt(unsigned char*enc_data, int data_len, unsigned char*key, unsigned char*decrypted)
  {
	  RSA* rsa = createRSA(key, 0);
	  int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
	  return result;
  }
  /*
** 私钥加密
*/
  unsigned char* utils_openssl::private_encrypt(string privateKay,string strData,int * outlen)
  {
	  std::string strRet;

	  RSA * pRSAPrivateKey = createRSA((unsigned char*)privateKay.c_str(), 0);

	  int nLen = RSA_size(pRSAPrivateKey);
	  unsigned char * pEncode = new unsigned char[nLen + 1];
	  *outlen = RSA_private_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPrivateKey, RSA_PKCS1_PADDING);
	 
	//  delete[] pEncode;
	  RSA_free(pRSAPrivateKey);
	
	  CRYPTO_cleanup_all_ex_data();
	  return pEncode;
  }

//公钥解密
  string utils_openssl::public_decrypt(unsigned char* enc_data, int data_len, unsigned char* key )
{
    RSA * rsa = createRSA(key, 1);
    int decryptLen = RSA_size(rsa);
    unsigned char*out =  (unsigned char *)malloc(decryptLen);
    unsigned char*enc_tmp =  (unsigned char *)malloc(decryptLen);
    if(NULL == out)
    {
        LOGD("pubkey_decrypt:malloc error!");
        return "";
    }
    string deContent="";
    int dataLen = data_len;
    for (int i = 0; i <= dataLen / decryptLen; i++) {
        int pos = i * decryptLen;
        if (pos == dataLen) {
            break;
        }
        int length = decryptLen;
        if (pos + decryptLen > dataLen) {
            length = dataLen - pos;
        }
        memset((void *)out, 0, decryptLen);
        memset((void *)enc_tmp, 0, decryptLen);

        memcpy(enc_tmp, enc_data+pos, length);
        int  result = RSA_public_decrypt(length, enc_tmp, out, rsa, RSA_PKCS1_PADDING);

        if(result>0)
        {
            deContent+=(char*)out;
        } else
        {
            LOGD("RSA_public_decrypt failed/n");
            int errorcode = ERR_get_error();
            //加载错误信息
          //  int loaderr =   ERR_load_ERR_strings();
            ERR_load_crypto_strings();
            // 获取错误号
            unsigned long ulErr = ERR_get_error();
            char szErrMsg[1024] = {0};
            char *pTmp = NULL;
            // 格式：error:errId:库:函数:原因
            pTmp = ERR_error_string(ulErr,szErrMsg);
            LOGE("rsa error string:%s/n",pTmp);
            //ERR_error_string_n();
            break;
        }
    }
    RSA_free(rsa);
	CRYPTO_cleanup_all_ex_data();
    free(out);
    free(enc_tmp);
    return deContent;
}
/** 判断文件是否存在
* @param file_path 文件名称，包括路径
* @ return 文件路径为空返回 -1 不存在返回 -1 存在返回 0;
**/
  int utils_openssl::is_file_exits(const char * file_path)
{
    if(file_path==NULL)
        return -1; 
#if defined(WIN32) || defined(_WIN32) || defined(WINDOWS) 
	if (_access(file_path, F_OK) == 0)
#else
    if(access(file_path, F_OK)==0)
#endif
    {
        return 0;
    }
    return -1;
}

  unsigned char * utils_openssl::readFile(string file, int *len)
{
    FILE *fp;
    fp = fopen(file.c_str(), "rb");
    if (fp != NULL) {
        fseek(fp, 0L, SEEK_END);
        unsigned long filesize = ftell(fp);
        *len = filesize;
        if (filesize > 0) {
            unsigned char *fileBuffer = new unsigned char[filesize + 1];
            rewind(fp);//rewind函数作用等同于 (void)fseek(stream, 0L, SEEK_SET);
            fileBuffer[filesize] = '\0';
            int ret = fread(fileBuffer, sizeof(char), filesize, fp);

            fclose(fp);
            fp = NULL;
            if (ret <= 0) {
                return NULL;
            }
            return fileBuffer;
        }

        fclose(fp);
        fp = NULL;
    }

    return NULL;
}

  bool  utils_openssl::writeFile(const char * path ,const char * data)
{
    FILE *fp;
    if((fp=fopen(path,"wb"))==NULL)
    {
        LOGE("file cannot open %s",path);
        return false;
    }
    else
    {
        fwrite(data,1,strlen(data),fp);
    }
    if(fclose(fp)!=0)
    {
        LOGD("file cannot be closed \n");
    }
    else
    {
        LOGD("file is now closed \n");
    }

    return true;
}

  /*   Byte值转换为bytes字符串
  *   @param src：Byte指针 srcLen:src长度 des:转换得到的bytes字符串
  **/
  void utils_openssl::Bytes2HexStr(unsigned char *src, int srcLen, unsigned char *des)
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

  /**
  * bytes字符串转换为Byte值
  * @param String src Byte字符串，每个Byte之间没有分隔符
  * @return byte[]
  */
  unsigned char * utils_openssl::hexStr2Bytes(string src)
  {
	  char *strEnd;
	  int m = 0;
	  int len = src.length() / 2;
	  unsigned char* ret = new unsigned char[len];

	  for (int i = 0; i<len; i++)
	  {
		  m = i * 2;
		  string subs = src.substr(m, 2);
		  ret[i] = strtol(subs.c_str(), &strEnd, 16);
	  }
	  return ret;
  }

  string utils_openssl::Base64Encode(const char * input, int length, bool with_new_line)
  {
	  BIO * bmem = NULL;
	  BIO * b64 = NULL;
	  BUF_MEM * bptr = NULL;

	  b64 = BIO_new(BIO_f_base64());
	  if (!with_new_line) {
		  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	  }
	  bmem = BIO_new(BIO_s_mem());
	  b64 = BIO_push(b64, bmem);
	  BIO_write(b64, input, length);
	  BIO_flush(b64);
	  BIO_get_mem_ptr(b64, &bptr);

	  //这里的第二个参数很重要，必须赋值
	  std::string result(bptr->data, bptr->length);
	  BIO_free_all(b64);
	  return result;
  }

  string utils_openssl::Base64Decode(const char * input, int length, bool with_new_line)
  {
	  BIO * b64 = NULL;
	  BIO * bmem = NULL;
	  unsigned char * buffer = (unsigned char *)malloc(length);
	  memset(buffer, 0, length);

	  b64 = BIO_new(BIO_f_base64());
	  if (!with_new_line) {
		  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	  }
	  bmem = BIO_new_mem_buf(input, length);
	  bmem = BIO_push(b64, bmem);
	  int ret = BIO_read(bmem, buffer, length);
	  //这里的第二个参数很重要，必须赋值
	  std::string result((char*)buffer, ret);

	  BIO_free_all(bmem);

	  return result;
  }

  int utils_openssl::aes_encrypt(const unsigned char* in, const unsigned char* key, const unsigned char* out, int inLen)
  {
	  if (!in || !key || !out) return 0;
	  unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
	  for (int i = 0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
		  iv[i] = 0;
	  AES_KEY aes;
	  if (AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0)
	  {
		  return 0;
	  }
	  int len = inLen;//这里的长度是char*in的长度，但是如果in中间包含'\0'字符的话

					  //那么就只会加密前面'\0'前面的一段，所以，这个len可以作为参数传进来，记录in的长度

					  //至于解密也是一个道理，光以'\0'来判断字符串长度，确有不妥，后面都是一个道理。
	  AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
	  return 1;
  }
  int utils_openssl::aes_decrypt(const unsigned char* in, const unsigned char* key, unsigned char* out, int inLen)
  {
	  if (!in || !key || !out) return 0;
	  unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
	  for (int i = 0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
		  iv[i] = 0;
	  AES_KEY aes;
	  if (AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
	  {
		  return 0;
	  }
	  int len = inLen;
	  AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
	  return 1;
  }
