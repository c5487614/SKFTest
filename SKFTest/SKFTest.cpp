// SKFTest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <gtest/gtest.h>
#include "skf.h"

HMODULE hmodule;
char* devName;
DEVHANDLE* devHandle;

TEST(LoadSKFLibrary,LoadSKFLibrary)
{
	char* dllName="mtoken_gm3000.dll";
	hmodule = LoadLibrary(dllName);
	EXPECT_NE(0,(int)hmodule);
}
TEST(SKF_DEV_MANAGE,SKF_EnumDev_Test)
{
	SKF_EnumDev skf_enumDev = SKF_EnumDev(GetProcAddress(hmodule,"SKF_EnumDev"));
	ULONG* pulSize = new ULONG();
	skf_enumDev(true,NULL,pulSize);
	ASSERT_NE(0,*pulSize);
	devName = (char*)malloc(*pulSize);
	skf_enumDev(true,devName,pulSize);

	EXPECT_STRNE("",devName);
}
TEST(SKF_DEV_MANAGE,SKF_ConnectDev_Test)
{
	ULONG result;
	SKF_ConnectDev skf_connetDev = SKF_ConnectDev(GetProcAddress(hmodule,"SKF_ConnectDev"));
	devHandle = new DEVHANDLE();
	result = skf_connetDev(devName,devHandle);
	EXPECT_EQ(0,(int)result);
	EXPECT_NE(0,(int)(*devHandle));
}

TEST(SKF_DEV_MANAGE,SKF_GetDevState_Test)
{
	ULONG* pulState = new ULONG();
	ULONG result;
	SKF_GetDevState skf_getDevState = SKF_GetDevState(GetProcAddress(hmodule,"SKF_GetDevState"));
	result = skf_getDevState(devName,pulState);
	EXPECT_EQ(0,(int)result);
	EXPECT_EQ(1,*pulState);
}
TEST(SKF_DEV_MANAGE,SKF_SetLabel_Test)
{
	ULONG* pulState = new ULONG();
	ULONG result;
	SKF_SetLabel skf_setLabel = SKF_SetLabel(GetProcAddress(hmodule,"SKF_SetLabel"));
	result = skf_setLabel(*devHandle,"LongmaiHID");
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_DEV_MANAGE,SKF_GetDevInfo_Test)
{
	ULONG result;
	DEVINFO* devInfo = new DEVINFO();
	SKF_GetDevInfo skf_getDevInfo = SKF_GetDevInfo(GetProcAddress(hmodule,"SKF_GetDevInfo"));
	result = skf_getDevInfo(*devHandle,devInfo);
	EXPECT_EQ(0,(int)result);
}


TEST(SKF_ACCESS_CONTROL,SKF_DEVAUTH_Test)
{
	ULONG result;
	
	/*BYTE pbRandom[32] = {0}; 
	SKF_GenRandom skf_genRandom = SKF_GenRandom(GetProcAddress(hmodule,"SKF_GenRandom"));
	result = skf_genRandom(*devHandle,pbRandom,8);
	EXPECT_EQ(0,(int)result);*/

	SKF_ConnectDev skf_connetDev = SKF_ConnectDev(GetProcAddress(hmodule,"SKF_ConnectDev"));
	devHandle = new DEVHANDLE();
	result = skf_connetDev(devName,devHandle);
	EXPECT_EQ(0,(int)result);

	BYTE* pbRandom =(BYTE*) malloc(sizeof(BYTE)*32);
	SKF_GenRandom skf_genRandom = SKF_GenRandom(GetProcAddress(hmodule,"SKF_GenRandom"));
	result = skf_genRandom(*devHandle,pbRandom,8);
	EXPECT_EQ(0,(int)result);

	HANDLE hKey = NULL;
	char *dev_auth_key = "1234567812345678";
	SKF_SetSymmKey skf_setSymmKey = SKF_SetSymmKey(GetProcAddress(hmodule,"SKF_SetSymmKey"));
	result = skf_setSymmKey(*devHandle,(unsigned char*)dev_auth_key,0x00000401,&hKey);
	EXPECT_EQ(0,(int)result);

	SKF_EncryptInit skf_encryptInit = SKF_EncryptInit(GetProcAddress(hmodule,"SKF_EncryptInit"));
	BLOCKCIPHERPARAM bp = {0};
	result = skf_encryptInit(hKey, bp);
	EXPECT_EQ(0,(int)result);

	SKF_Encrypt skf_encrypt = SKF_Encrypt(GetProcAddress(hmodule,"SKF_Encrypt"));
	BYTE szEncryptedData[256] = {0};
	ULONG ulEncryptedDataLen = 256;
	result = skf_encrypt(hKey, pbRandom, 16, szEncryptedData, &ulEncryptedDataLen);
	EXPECT_EQ(0,(int)result);

	SKF_DevAuth skf_devAuth = SKF_DevAuth(GetProcAddress(hmodule,"SKF_DevAuth"));
	result = skf_devAuth(*devHandle,szEncryptedData,ulEncryptedDataLen);
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_ACCESS_CONTROL,SKF_ChangeDevAuthKey_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_ACCESS_CONTROL,SKF_ChangePIN_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_ACCESS_CONTROL,SKF_GetPINInfo_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_ACCESS_CONTROL,SKF_VerifyPIN_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_ACCESS_CONTROL,SKF_UnbolckPIN_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_ACCESS_CONTROL,SKF_RemoteUnbolckPIN_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_ACCESS_CONTROL,SKF_ClearSecureState_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_APPLICATION_MANAGE,SKF_CreateApplication_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_APPLICATION_MANAGE,SKF_CreateApplication_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_DEV_MANAGE,SKF_DisConnectDev_Test)
{
	ULONG result;
	SKF_DisConnectDev skf_disConnetDev = SKF_DisConnectDev(GetProcAddress(hmodule,"SKF_DisConnectDev"));
	result = skf_disConnetDev(*devHandle);
	EXPECT_EQ(0,(int)result);
}
int _tmain(int argc, _TCHAR* argv[])
{
	testing::InitGoogleTest(&argc, argv);
	RUN_ALL_TESTS();
	getchar();

    return 0;
}

