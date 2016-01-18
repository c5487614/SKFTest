#ifndef __SKF_H__
#define __SKF_H__

#ifdef __cplusplus
extern "C" {
#endif

//define 常量
#define DEVAPI __stdcall

#define TRUE  1
#define FALSE 0
#define ADMIN_TYPE  0
#define USER_TYPE   1

#define SECURE_NEVER_ACCOUNT  0x00000000 //不允许
#define SECURE_ADM_ACCOUNT    0x00000001 //管理员权限
#define SECURE_USER_ACCOUNT   0x00000010 //用户权限
#define SECURE_ANYONE_ACCOUNT 0x000000FF //任何人

#define DEV_ABSENT_STATE	0x00000000  //设备不存在
#define DEV_PRESENT_STATE	0x00000001  //设备存在
#define DEV_UNKNOW_STATE	0x00000002  //设备状态未知


#define MAX_RSA_MODULUS_LEN  256			//为算法模数的最大长度
#define MAX_RSA_EXPONENT_LEN 4				//为算法指数的最大长
#define ECC_MAX_XCOORDINATE_BITS_LEN 512	//为ECC算法X坐标的最大长度
#define ECC_MAX_YCOORDINATE_BITS_LEN 512	//为ECC算法Y坐标的最大长度
#define ECC_MAX_MODULUS_BITS_LEN 512		//为ECC算法模数的最大长度
#define MAX_IV_LEN 32						//为初始化向量的最大长度

	typedef  signed char 	INT8;
	typedef  signed short   INT16;
	typedef  signed int		INT32;
	typedef  unsigned char 	UINT8;
	typedef  unsigned short UINT16;
	typedef  unsigned int   UINT32;
	typedef  int            BOOL;

	typedef unsigned char	BYTE;
	typedef signed short	SHORT;
	typedef unsigned short	USHORT;
	typedef unsigned int	UINT;
	typedef unsigned short	WORD;
	typedef char			CHAR;
	typedef unsigned char	UCHAR;
	typedef signed long		LONG;
	typedef unsigned long	ULONG;
	typedef unsigned long	DWORD;

	typedef UINT32	FLAGS;
 	typedef CHAR *	LPSTR;
	typedef void *	HANDLE;
	typedef HANDLE	DEVHANDLE;
	typedef HANDLE	HAPPLICATION;
	typedef HANDLE	HCONTAINER;


	typedef struct Struct_Version{
		BYTE major;
		BYTE minor;
	}VERSION;

	typedef struct Struct_DEVINFO{
		VERSION Version;              // 版本号,数据结构版本号，本结构的版本号为1.0
		CHAR Manufacturer[64];        // 设备厂商信息,以’\0’为结束符的ASCII字符串
		CHAR Issuer[64];              // 发行厂商信息,以’\0’为结束符的ASCII字符串
		CHAR Label[32];				  // 设备标签,以’\0’为结束符的ASCII字符串
		CHAR SerialNumber[32];        // 序列号,以’\0’为结束符的ASCII字符串
		VERSION HWVersion;            // 设备硬件版本
		VERSION FirmwareVersion;      // 设备本身固件版本
		ULONG AlgSymCap;              // 分组密码算法标识
		ULONG AlgAsymCap;             // 非对称密码算法标识
		ULONG AlgHashCap;             // 密码杂凑算法标识
		ULONG DevAuthAlgId;           // 设备认证使用的分组密码算法标识
		ULONG TotalSpace;             // 设备总空间大小
		ULONG FreeSpace;              // 用户可用空间大小 
		ULONG MaxECCBufferSize;       // 能够处理的ECC加密数据大小
		ULONG MaxBufferSize;          // 能够处理的分组运算和杂凑运算的数据大小
		BYTE Reserved[64];            // 保留扩展
	}DEVINFO,*PDEVINFO;

	typedef struct Struct_RSAPUBLICKEYBLOB{
		ULONG AlgID;								//算法标识号
		ULONG BitLen;								//模数的实际位长度,必须是8的倍数
		BYTE Modulus[MAX_RSA_MODULUS_LEN];			//模数n = p * q
		BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];	//公开密钥e
	}RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

	typedef struct Struct_RSAPRIVATEKEYBLOB{
		ULONG AlgID;								//算法标识号
		ULONG BitLen;								//模数的实际位长度
		BYTE Modulus[MAX_RSA_MODULUS_LEN];			//模数n = p * q
		BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];	//公开密钥e
		BYTE PrivateExponent[MAX_RSA_MODULUS_LEN];	//私有密钥d
		BYTE Prime1[MAX_RSA_MODULUS_LEN/2];			//素数p
		BYTE Prime2[MAX_RSA_MODULUS_LEN/2];			//素数q
		BYTE Prime1Exponent[MAX_RSA_MODULUS_LEN/2];	//d mod (p-1)的值
		BYTE Prime2Exponent[MAX_RSA_MODULUS_LEN/2];	//d mod (q -1)的值
		BYTE Coefficient[MAX_RSA_MODULUS_LEN/2];	//q模p的乘法逆元
	}RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

	typedef struct Struct_RSAPARAMETERS
	{
		BYTE PrivateExponent[MAX_RSA_MODULUS_LEN];
		BYTE Prime1[MAX_RSA_MODULUS_LEN/2];
		BYTE Prime2[MAX_RSA_MODULUS_LEN/2];
		BYTE Prime1Exponent[MAX_RSA_MODULUS_LEN/2];
		BYTE Prime2Exponent[MAX_RSA_MODULUS_LEN/2];	
		BYTE Coefficient[MAX_RSA_MODULUS_LEN/2];
		BYTE Modulus[MAX_RSA_MODULUS_LEN];
		BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];
	}RSAPARAMETERS, *PRSAPARAMETERS;


	typedef struct Struct_ECCPRIVATEKEYBLOB{
		ULONG BitLen;										//模数的实际位长度
		BYTE PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];		//私有密钥
	}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

	typedef struct Struct_ECCPUBLICKEYBLOB{
		ULONG BitLen;										//模数的实际位长度必须是8的倍数
		BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];	//曲线上点的X坐标
		BYTE YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];	//曲线上点的Y坐标
	}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

	typedef struct Struct_ECCCIPHERBLOB{
		BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];	//与y组成椭圆曲线上的点（x，y）
		BYTE YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];	//与x组成椭圆曲线上的点（x，y）
		BYTE HASH[32];										//明文的杂凑值
		ULONG CipherLen;									//密文数据长度
		BYTE Cipher[150];									//密文数据,实际长度为CipherLen
	} ECCCIPHERBLOB, *PECCCIPHERBLOB;

	typedef struct Struct_ECCSIGNATUREBLOB{
		BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN/8];				//签名结果的r部分
		BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN/8];				//签名结果的s部分
	} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

	typedef struct Struct_BLOCKCIPHERPARAM{
		BYTE IV[MAX_IV_LEN];	//初始向量			
		ULONG IVLen;			//初始向量实际长度（按字节计算）
		ULONG PaddingType;		//填充方式，0表示不填充，1表示按照PKCS#5方式进行填充
		ULONG FeedBitLen;		//反馈值的位长度（按位计算）只针对OFB、CFB模式
	} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

	typedef struct SKF_ENVELOPEDKEYBLOB{
		ULONG Version; // 当前版本为 1
		ULONG ulSymmAlgID; // 对称算法标识，限定ECB模式
		ULONG ulBits; // 加密密钥对的密钥位长度
		BYTE cbEncryptedPriKey[64]; // 加密密钥对私钥的密文
		ECCPUBLICKEYBLOB PubKey; // 加密密钥对的公钥
		ECCCIPHERBLOB ECCCipherBlob; // 用保护公钥加密的对称密钥密文。
	}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

	typedef struct Struct_FILEATTRIBUTE{
		CHAR FileName[32];	//文件名,以‘\0’结束的ASCII字符串，最大长度为32
		ULONG FileSize;		//文件大小
		ULONG ReadRights;	//读取权限
		ULONG WriteRights;	//写入权限
	} FILEATTRIBUTE, *PFILEATTRIBUTE;




ULONG DEVAPI SKF_SelectMF(DEVHANDLE hDev);

//错误代码定义和说明
#define SAR_OK                        0x00000000    //成功
#define SAR_FAIL                      0x0A000001	//失败
#define SAR_UNKNOWNERR                0x0A000002	//异常错误
#define SAR_NOTSUPPORTYETERR          0x0A000003	//不支持的服务
#define SAR_FILEERR                   0x0A000004	//文件操作错误
#define SAR_INVALIDHANDLEERR          0x0A000005	//无效的句柄
#define SAR_INVALIDPARAMERR           0x0A000006	//无效的参数
#define SAR_READFILEERR               0x0A000007	//读文件错误
#define SAR_WRITEFILEERR              0x0A000008	//写文件错误
#define SAR_NAMELENERR                0x0A000009	//名称长度错误
#define SAR_KEYUSAGEERR               0x0A00000A	//密钥用途错误
#define SAR_MODULUSLENERR             0x0A00000B	//模的长度错误
#define SAR_NOTINITIALIZEERR          0x0A00000C	//未初始化
#define SAR_OBJERR                    0x0A00000D	//对象错误
#define SAR_MEMORYERR                 0x0A00000E	//内存错误
#define SAR_TIMEOUTERR                0x0A00000F	//超时
#define SAR_INDATALENERR              0x0A000010	//输入数据长度错误
#define SAR_INDATAERR                 0x0A000011	//输入数据错误
#define SAR_GENRANDERR                0x0A000012	//生成随机数错误
#define SAR_HASHOBJERR                0x0A000013	//HASH对象错
#define SAR_HASHERR                   0x0A000014	//HASH运算错误
#define SAR_GENRSAKEYERR              0x0A000015	//产生RSA密钥错
#define SAR_RSAMODULUSLENERR          0x0A000016	//RSA密钥模长错误
#define SAR_CSPIMPRTPUBKEYERR         0x0A000017	//CSP服务导入公钥错误
#define SAR_RSAENCERR                 0x0A000018	//RSA加密错误
#define SAR_RSADECERR                 0x0A000019	//RSA解密错误
#define SAR_HASHNOTEQUALERR           0x0A00001A	//HASH值不相等
#define SAR_KEYNOTFOUNTERR            0x0A00001B	//密钥未发现
#define SAR_CERTNOTFOUNTERR           0x0A00001C	//证书未发现
#define SAR_NOTEXPORTERR              0x0A00001D	//对象未导出
#define SAR_DECRYPTPADERR             0x0A00001E	//解密时做补丁错误
#define SAR_MACLENERR                 0x0A00001F	//MAC长度错误
#define SAR_BUFFER_TOO_SMALL          0x0A000020	//缓冲区不足
#define SAR_KEYINFOTYPEERR            0x0A000021	//密钥类型错误
#define SAR_NOT_EVENTERR              0x0A000022	//无事件错误
#define SAR_DEVICE_REMOVED            0x0A000023	//设备已移除
#define SAR_PIN_INCORRECT             0x0A000024	//PIN不正确
#define SAR_PIN_LOCKED                0x0A000025	//PIN被锁死
#define SAR_PIN_INVALID               0x0A000026	//PIN无效
#define SAR_PIN_LEN_RANGE             0x0A000027	//PIN长度错误
#define SAR_USER_ALREADY_LOGGED_IN    0x0A000028	//用户已经登录
#define SAR_USER_PIN_NOT_INITIALIZED  0x0A000029	//没有初始化用户口令
#define SAR_USER_TYPE_INVALID         0x0A00002A	//PIN类型错误
#define SAR_APPLICATION_NAME_INVALID  0x0A00002B	//应用名称无效
#define SAR_APPLICATION_EXISTS        0x0A00002C	//应用已经存在
#define SAR_USER_NOT_LOGGED_IN        0x0A00002D	//用户没有登录
#define SAR_APPLICATION_NOT_EXISTS    0x0A00002E	//应用不存在
#define SAR_FILE_ALREADY_EXIST        0x0A00002F	//文件已经存在
#define SAR_NO_ROOM                   0x0A000030	//空间不足
#define SAR_FILE_NOT_EXIST            0x0A000031	//文件不存在
#define SAR_REACH_MAX_CONTAINER_COUNT 0x0A000032	//已达到最大可管理容器数

//标签 标识符 描述
//分组密码算法标识
#define SGD_SM1_ECB		0x00000101	//SM1 算法ECB 加密模式
#define SGD_SM1_CBC		0x00000102	//SM1 算法CBC 加密模式
#define SGD_SM1_CFB		0x00000104	//SM1 算法CFB 加密模式
#define SGD_SM1_OFB		0x00000108	//SM1 算法OFB 加密模式
#define SGD_SM1_MAC		0x00000110	//SM1算法MAC运算
#define SGD_SSF33_ECB	0x00000201	//SSF33算法ECB加密模式
#define SGD_SSF33_CBC	0x00000202	//SSF33算法CBC加密模式
#define SGD_SSF33_CFB	0x00000204	//SSF33算法CFB加密模式
#define SGD_SSF33_OFB	0x00000208	//SSF33算法OFB加密模式
#define SGD_SSF33_MAC	0x00000210	//SSF33算法MAC运算
#define SGD_SMS4_ECB	0x00000401	//SMS4算法ECB加密模式
#define SGD_SMS4_CBC	0x00000402	//SMS4算法CBC加密模式
#define SGD_SMS4_CFB	0x00000404	//SMS4算法CFB加密模式
#define SGD_SMS4_OFB	0x00000408	//SMS4算法OFB加密模式
#define SGD_SMS4_MAC	0x00000410	//SMS4算法MAC运算

#define SGD_TDES_ECB    0x00000801  //TDES 算法ECB 加密模式

//非对称密码算法标识
#define SGD_RSA			0x00010000		//RSA算法
#define SGD_SM2_1		0x00020100		//椭圆曲线签名算法
#define SGD_SM2_2		0x00020200		//椭圆曲线密钥交换协议
#define SGD_SM2_3		0x00020400		//椭圆曲线加密算法

//密码杂凑算法标识
#define SGD_SM3			0x00000001		//SM3杂凑算法
#define SGD_SHA1		0x00000002		//SHA1杂凑算法
#define SGD_SHA256		0x00000004		//SHA256杂凑算法


typedef ULONG (DEVAPI *SKF_EnumDev)(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);//枚举设备接口声明
typedef ULONG (DEVAPI *SKF_ConnectDev) (LPSTR szName, DEVHANDLE *phDev);
typedef ULONG (DEVAPI *SKF_DisConnectDev) (DEVHANDLE hDev);
typedef ULONG (DEVAPI *SKF_CreateApplication)(DEVHANDLE hDev, LPSTR szAppName, LPSTR szAdminPin, DWORD dwAdminPinRetryCount,LPSTR szUserPin, DWORD dwUserPinRetryCount,DWORD dwCreateFileRights, HAPPLICATION *phApplication);
typedef ULONG (DEVAPI *SKF_GetDevState)(LPSTR szDevName, ULONG *pulDevState);
typedef ULONG (DEVAPI *SKF_SetLabel) (DEVHANDLE hDev, LPSTR szLabel);
typedef ULONG (DEVAPI *SKF_GetDevInfo) (DEVHANDLE hDev, DEVINFO *pDevInfo);
typedef ULONG (DEVAPI *SKF_DevAuth) (DEVHANDLE hDev, BYTE *pbAuthData,ULONG ulLen);
typedef ULONG (DEVAPI *SKF_VerifyPIN) (HAPPLICATION hApplication, ULONG ulPINType, LPSTR szPIN, ULONG *pulRetryCount);
typedef ULONG (DEVAPI *SKF_EnumApplication)(DEVHANDLE hDev, LPSTR szAppName,ULONG *pulSize);
typedef ULONG (DEVAPI *SKF_OpenApplication)(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication);
typedef ULONG (DEVAPI *SKF_CloseApplication)(HAPPLICATION hApplication);
typedef ULONG (DEVAPI *SKF_CreateContainer) (HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);
typedef ULONG (DEVAPI *SKF_DeleteContainer)(HAPPLICATION hApplication, LPSTR szContainerName);
typedef ULONG (DEVAPI *SKF_EnumContainer) (HAPPLICATION hApplication, LPSTR szContainerName, ULONG *pulSize);
typedef ULONG (DEVAPI *SKF_OpenContainer)(HAPPLICATION hApplication,LPSTR szContainerName,HCONTAINER *phContainer);
typedef ULONG (DEVAPI *SKF_CloseContainer)(HCONTAINER hContainer);
typedef ULONG (DEVAPI *SKF_DeleteApplication)(DEVHANDLE hDev, LPSTR szAppName);

typedef ULONG (DEVAPI *SKF_ImportCertificate)(HCONTAINER hContainer, BOOL bSignFlag,  BYTE* pbCert, ULONG ulCertLen);
typedef ULONG (DEVAPI *SKF_ExportCertificate)(HCONTAINER hContainer, BOOL bSignFlag,  BYTE* pbCert, ULONG *pulCertLen);
typedef ULONG (DEVAPI *SKF_GenRandom) (DEVHANDLE hDev, BYTE *pbRandom,ULONG ulRandomLen);
typedef ULONG (DEVAPI *SKF_GenECCKeyPair) (HCONTAINER hContainer, ULONG ulAlgId,ECCPUBLICKEYBLOB *pBlob);
typedef ULONG (DEVAPI *SKF_ECCSignData) (HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature);
typedef ULONG (DEVAPI *SKF_ExtECCVerify) (DEVHANDLE hDev, ECCPUBLICKEYBLOB*  pECCPubKeyBlob,BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);
typedef ULONG (DEVAPI *SKF_ExportPublicKey) (HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbBlob, ULONG* pulBlobLen);

typedef ULONG (DEVAPI *SKF_DigestInit)(DEVHANDLE hDev, ULONG ulAlgID,  ECCPUBLICKEYBLOB *pPubKey, unsigned char *pucID, ULONG ulIDLen, HANDLE *phHash);
typedef ULONG (DEVAPI *SKF_Digest) (HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen);
typedef ULONG (DEVAPI *SKF_DigestUpdate) (HANDLE hHash, BYTE *pbData, ULONG  ulDataLen);
typedef ULONG (DEVAPI *SKF_DigestFinal) (HANDLE hHash, BYTE *pHashData, ULONG  *pulHashLen);
typedef ULONG (DEVAPI *SKF_ChangeDevAuthKey)(DEVHANDLE hDev, BYTE *pbKeyValue, ULONG ulKeyLen);

typedef ULONG (DEVAPI *SKF_SetSymmKey) (DEVHANDLE hDev, BYTE* pbKey, ULONG ulAlgID, HANDLE* phKey);
typedef ULONG (DEVAPI *SKF_EncryptInit) (HANDLE hKey, BLOCKCIPHERPARAM EncryptParam);
typedef ULONG (DEVAPI *SKF_Encrypt)(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);
typedef ULONG (DEVAPI *SKF_EncryptUpdate)(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);
typedef ULONG (DEVAPI *SKF_EncryptFinal)(HANDLE hKey, BYTE *pbEncryptedData, ULONG *ulEncryptedDataLen );
typedef ULONG (DEVAPI *SKF_GenRandom) (DEVHANDLE hDev, BYTE *pbRandom,ULONG ulRandomLen);

#ifdef __cplusplus
}       // Balance extern "C" above
#endif

#endif