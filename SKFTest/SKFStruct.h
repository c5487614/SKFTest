#include "WinDef.h"
#include "WinBase.h"

typedef HANDLE DEVHANDLE;
typedef HANDLE HAPPLICATION;
typedef HANDLE HCONTAINER;
#define MAX_IV_LEN 32
typedef struct Struct_Version{ 
	BYTE major;
	BYTE minor;
}VERSION;
typedef struct Struct_DEVINFO{
	VERSION	Version;
	CHAR	Manufacturer[64]; CHAR	Issuer[64];
	CHAR	Label[32];
	CHAR	SerialNumber[32]; VERSION	HWVersion;
	VERSION	FirmwareVersion; ULONG	AlgSymCap;
	ULONG	AlgAsymCap; ULONG	AlgHashCap; ULONG	DevAuthAlgId; ULONG	TotalSpace; ULONG	FreeSpace; BYTE	Reserved[64];
}DEVINFO,*PDEVINFO;

typedef struct Struct_BLOCKCIPHERPARAM{
		BYTE IV[MAX_IV_LEN];	//初始向量			
		ULONG IVLen;			//初始向量实际长度（按字节计算）
		ULONG PaddingType;		//填充方式，0表示不填充，1表示按照PKCS#5方式进行填充
		ULONG FeedBitLen;		//反馈值的位长度（按位计算）只针对OFB、CFB模式
	} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

//device manage
//enumeric device
typedef ULONG (_stdcall *SKF_EnumDev)(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);
//connect device
typedef ULONG (_stdcall *SKF_ConnectDev)(LPSTR szDevName, DEVHANDLE *phDev);
//disconnect device
typedef ULONG (_stdcall *SKF_DisConnectDev)(DEVHANDLE devHandle);
//get dev status
typedef ULONG (_stdcall *SKF_GetDevState)(LPSTR szDevName,ULONG *pulDevState);
//set dev label
typedef ULONG (_stdcall *SKF_SetLabel)(DEVHANDLE devHandle,LPSTR szLabel);
//get dev info
typedef ULONG (_stdcall *SKF_GetDevInfo)(DEVHANDLE devHandle,DEVINFO* szLabel);
//lock dev-not test
typedef ULONG (_stdcall *SKF_LockDev)(DEVHANDLE devHandle,ULONG ulTimeOut);
//unlock dev-not test
typedef ULONG (_stdcall *SKF_UnlockDev)(DEVHANDLE devHandle);
//unlock dev-not test
typedef ULONG (_stdcall *SKF_Transmit)(DEVHANDLE devHandle,BYTE* pbCommand,ULONG ulCommandLen,BYTE* pbData,ULONG* plDataLen);
//device manage end

//access control
//dev auth
typedef ULONG (_stdcall *SKF_DevAuth)(DEVHANDLE devHandle,BYTE* pbAuthData,ULONG ulLen);
//change dev auth key-not test
typedef ULONG (_stdcall *SKF_ChangeDevAuthKey)(DEVHANDLE devHandle,BYTE* pbKeyValue,ULONG ulLen);
//access control end

//crypto service
//gen random
typedef ULONG (_stdcall *SKF_GenRandom)(DEVHANDLE devHandle,BYTE* pbRandom,ULONG ulRandomLen);
//set symm key
typedef ULONG (_stdcall *SKF_SetSymmKey)(DEVHANDLE devHandle,unsigned char* pcKey,int encryptMethod,HANDLE* hkey);

//crypto service end