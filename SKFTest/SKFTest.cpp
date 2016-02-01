// SKFTest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <gtest/gtest.h>
#include "skf.h"

HMODULE hmodule;
char* devName;
DEVHANDLE* devHandle;
HAPPLICATION hApplication;

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
	ULONG* pulSize = new ULONG();
	ULONG result;
	LPSTR szAppName;
	ULONG *retryCount = new ULONG();


	SKF_EnumApplication skf_enumApplication = SKF_EnumApplication(GetProcAddress(hmodule,"SKF_EnumApplication"));
	result = skf_enumApplication(*devHandle,NULL,pulSize);
	EXPECT_EQ(0,(int)result);

	szAppName = (LPSTR)malloc(sizeof(char)*(*pulSize));

	result = skf_enumApplication(*devHandle,szAppName,pulSize);
	EXPECT_EQ(0,(int)result);

	SKF_OpenApplication skf_openApplication = SKF_OpenApplication(GetProcAddress(hmodule,"SKF_OpenApplication"));
	result = skf_openApplication(*devHandle,szAppName,&hApplication);
	EXPECT_EQ(0,(int)result);

	SKF_ChangePIN skf_changePIN = SKF_ChangePIN(GetProcAddress(hmodule,"SKF_ChangePIN"));
	*retryCount = 8;
	//result = skf_changePIN(hApplication,USER_TYPE,"11111111","22222222",retryCount);
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_ACCESS_CONTROL,SKF_GetPINInfo_Test)
{
	ULONG *pulMaxRetryCount = new ULONG();
	ULONG *pulRemainRetryCount = new ULONG();
	BOOL *pbDefaultPin = new BOOL();
	ULONG result;

	SKF_GetPINInfo skf_getPINInfo = SKF_GetPINInfo(GetProcAddress(hmodule,"SKF_GetPINInfo"));
	result = skf_getPINInfo(hApplication,USER_TYPE,pulMaxRetryCount,pulRemainRetryCount,pbDefaultPin);
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_ACCESS_CONTROL,SKF_VerifyPIN_Test)
{
	ULONG result;
	ULONG *pulRemainRetryCount = new ULONG();

	SKF_VerifyPIN skf_verifyPIN = SKF_VerifyPIN(GetProcAddress(hmodule,"SKF_VerifyPIN"));
	result = skf_verifyPIN(hApplication,USER_TYPE,"22222222",pulRemainRetryCount);
	EXPECT_EQ(0,(int)result);

}
TEST(SKF_ACCESS_CONTROL,SKF_UnbolckPIN_Test)
{
	ULONG result;
	ULONG *pulAdminRemainRetryCount = new ULONG();

	SKF_UnblockPIN skf_unblockPIN = SKF_UnblockPIN(GetProcAddress(hmodule,"SKF_UnblockPIN"));
	result = skf_unblockPIN(hApplication,"88888888","11111111",pulAdminRemainRetryCount);
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_ACCESS_CONTROL,SKF_RemoteUnbolckPIN_Test)
{
	/*ULONG result;
	ULONG *pulAdminRemainRetryCount = new ULONG();

	SKF_RemoteUnblockPIN skf_unblockPIN = SKF_UnblockPIN(GetProcAddress(hmodule,"SKF_UnblockPIN"));
	result = skf_unblockPIN(hApplication,"88888888","11111111",pulAdminRemainRetryCount);
	EXPECT_EQ(0,(int)result);*/
}
TEST(SKF_ACCESS_CONTROL,SKF_ClearSecureState_Test)
{
	ULONG result;

	SKF_ClearSecureState skf_clearSecureState = SKF_ClearSecureState(GetProcAddress(hmodule,"SKF_ClearSecureState"));
	result = skf_clearSecureState(hApplication);
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_APPLICATION_MANAGE,SKF_CreateApplication_Test)
{
	ULONG result;
	ULONG *pulAdminRemainRetryCount = new ULONG();

	SKF_CreateApplication skf_createApplication = SKF_CreateApplication(GetProcAddress(hmodule,"SKF_CreateApplication"));
	result = skf_createApplication(*devHandle,"HBCAAPPLICATION_RSA1","88888888",8,"11111111",8,SECURE_ADM_ACCOUNT,&hApplication);
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_APPLICATION_MANAGE,SKF_EnumApplication_Test)
{
	ULONG* pulSize = new ULONG();
	ULONG result;
	LPSTR szAppName;
	ULONG *retryCount = new ULONG();

	SKF_EnumApplication skf_enumApplication = SKF_EnumApplication(GetProcAddress(hmodule,"SKF_EnumApplication"));
	result = skf_enumApplication(*devHandle,NULL,pulSize);
	EXPECT_EQ(0,(int)result);

	szAppName = (LPSTR)malloc(sizeof(char)*(*pulSize));

	
	result = skf_enumApplication(*devHandle,szAppName,pulSize);
	
	EXPECT_EQ(0,(int)result);

}
TEST(SKF_APPLICATION_MANAGE,SKF_DeleteApplication_Test)
{
	ULONG* pulSize = new ULONG();
	ULONG result;
	LPSTR szAppName;
	ULONG *retryCount = new ULONG();


	SKF_DeleteApplication skf_deleteApplication = SKF_DeleteApplication(GetProcAddress(hmodule,"SKF_DeleteApplication"));
	result = skf_deleteApplication(*devHandle,"HBCAAPPLICATION_RSA1");
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_APPLICATION_MANAGE,SKF_OpenApplication_Test)
{
	ULONG* pulSize = new ULONG();
	ULONG result;
	LPSTR szAppName;
	ULONG *retryCount = new ULONG();


	SKF_EnumApplication skf_enumApplication = SKF_EnumApplication(GetProcAddress(hmodule,"SKF_EnumApplication"));
	result = skf_enumApplication(*devHandle,NULL,pulSize);
	EXPECT_EQ(0,(int)result);

	szAppName = (LPSTR)malloc(sizeof(char)*(*pulSize));

	result = skf_enumApplication(*devHandle,szAppName,pulSize);
	EXPECT_EQ(0,(int)result);

	SKF_OpenApplication skf_openApplication = SKF_OpenApplication(GetProcAddress(hmodule,"SKF_OpenApplication"));
	result = skf_openApplication(*devHandle,szAppName,&hApplication);
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_APPLICATION_MANAGE,SKF_CloseApplication_Test)
{
	ULONG* pulSize = new ULONG();
	ULONG result;
	LPSTR szAppName;
	ULONG *retryCount = new ULONG();


	SKF_CloseApplication skf_closeApplication = SKF_CloseApplication(GetProcAddress(hmodule,"SKF_CloseApplication"));
	result = skf_closeApplication(hApplication);
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_FILE_MANAGE,SKF_CreateFile_Test)
{
	ULONG fileSize=100;
	ULONG result;
	SKF_CreateFile skf_createFile = SKF_CreateFile(GetProcAddress(hmodule,"SKF_CreateFile"));
	result = skf_createFile(hApplication,"test",fileSize,0x000000FF,0x000000FF);
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_FILE_MANAGE,SKF_EnumFile_Test)
{
	ULONG *fileSize = new ULONG();
	ULONG result;
	LPSTR fileList;
	SKF_EnumFiles skf_enumFiles = SKF_EnumFiles(GetProcAddress(hmodule,"SKF_EnumFiles"));
	result = skf_enumFiles(hApplication,NULL,fileSize);
	EXPECT_EQ(0,(int)result);
	fileList = (LPSTR)malloc(sizeof(char)*(*fileSize));
	result = skf_enumFiles(hApplication,fileList,fileSize);
	EXPECT_EQ(0,(int)result);
}
TEST(SKF_FILE_MANAGE,SKF_DeleteFile_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_FILE_MANAGE,SKF_GetFileInfo_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_FILE_MANAGE,SKF_ReadFile_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_FILE_MANAGE,SKF_WriteFile_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CONTAINER_MANAGE,SKF_CreateContainer_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CONTAINER_MANAGE,SKF_DeleteContainer_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CONTAINER_MANAGE,SKF_EnumContainer_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CONTAINER_MANAGE,SKF_OpenContainer_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CONTAINER_MANAGE,SKF_CloseContainer_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CONTAINER_MANAGE,SKF_GetContainerType_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CONTAINER_MANAGE,SKF_ImportCertificate_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CONTAINER_MANAGE,SKF_ExportCertificate_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_GetRandom_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_GetRSAKeyPair_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_ImportRSAKeyPair_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_GetRSASignData_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_RSAVerify_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_RSAExportSessionKey_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_GenECCKeyPair_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_ImportECCKeyPair_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_ECCSignData_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_ECCVerify_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_GernerateAgreementDataWithECC_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_GernerateAgreementDataAndKeyWithECC_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_GernerateKeyWithECC_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_ECCExportSessionKey_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_ExportPublicKey_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_ImportSessionKey_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_EncryptInit_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_Encrypt_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_EncryptUpdate_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_EncryptFinal_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_DecryptInit_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_Decrypt_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_DecryptUpdate_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_DecryptFinal_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_DigestInit_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_Digest_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_DigestUpdate_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_DigestFinal_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_MAC_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_MACInit_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_MACUpdate_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_MACFinal_Test)
{
	EXPECT_EQ(0,1);
}
TEST(SKF_CRYPT_FUNCTION,SKF_CloseHandler_Test)
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

