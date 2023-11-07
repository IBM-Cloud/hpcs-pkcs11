/****************************************************************
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * pkcs11-object.c
 *
 * A sample application to interact with the HPCS PKCS11 library
 * 
 * Compile using:
 * gcc -o pkcs11-object pkcs11-object.c -ldl
 * 
 * Updates to be made within this source file:
 * Replace the text <so-user-api-key> with the SO user's PIN.
 * Replace the text <normal-user-api-key> with the normal user's PIN.
 * Replace the text <pkcs11-library> with name of your pkcs11 library.
 * 
 * Ensure that your pkcs11 library is in your library path (LD_LIBRARY_PATH)
 * and the grep11client.yaml PKCS11 configuration file is in the /etc/ep11client directory. You may
 * need to create the /etc/ep11client directory, if it does not exist.
 *
 * NOTE: This sample code is expecting a default library name of pkcs11-grep11.so (See the pkcs11LibName variable).
 *       Feel free to change the name to match your pkcs11 library name.
 *
 * Please refer to https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-set-up-pkcs-api
 * for more information about the setup of the PKCS11 library and its configuration file.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>
#include <sys/timeb.h>
#include "sample.h"

CK_FUNCTION_LIST  *funcs;
CK_BYTE           tokenNameBuf[32];
const char        tokenName[] = "testToken";

int main( int argc, char **argv )
{
    CK_C_INITIALIZE_ARGS  initArgs;
    CK_RV                   rc;
    CK_FLAGS                flags = 0;
    CK_SESSION_HANDLE       session;
    CK_OBJECT_HANDLE        pubObject;
    static CK_BBOOL         isTrue = TRUE;
    static CK_BBOOL         isFalse = FALSE;

    CK_RV                   (*pFunc)();
    void                    *pkcs11Lib;
    CK_UTF8CHAR_PTR         soPin = (unsigned char *) "<so-user-api-key>";
    CK_UTF8CHAR_PTR         userPin = (unsigned char *) "<normal-user-api-key>";
    char                    pkcs11LibName[] = "pkcs11-grep11.so";

    printf("Opening the PKCS11 library...\n");
    pkcs11Lib = dlopen(pkcs11LibName, RTLD_NOW);
    if ( pkcs11Lib == NULL ) {
        printf("%s not found. Ensure that the PKCS11 library is in the system library path or LD_LIBRARY_PATH\n", pkcs11LibName);
        return !CKR_OK;
    }

    printf("Getting the PKCS11 function list...\n");
    pFunc = (CK_RV (*)())dlsym(pkcs11Lib, "C_GetFunctionList");
    if (pFunc == NULL ) {
        printf("C_GetFunctionList() not found in module %s\n", pkcs11LibName);
        return !CKR_OK;
    }
    rc = pFunc(&funcs);
    if (rc != CKR_OK) {
        printf("error C_GetFunctionList: rc=0x%04lx\n", rc );
        return !CKR_OK;
    }

    printf("Initializing the PKCS11 environment...\n");
    memset( &initArgs, 0x0, sizeof(initArgs) );
    rc = funcs->C_Initialize( &initArgs );
    if (rc != CKR_OK) {
        printf("error C_Initialize: rc=0x%04lx\n", rc );
        return !CKR_OK;
    }

    printf("Initializing the token... \n");
    memset(tokenNameBuf, ' ', sizeof(tokenNameBuf)); /* Token name is left justified, padded with blanks */
    memcpy(tokenNameBuf, tokenName, strlen(tokenName));

    /* C_InitToken cleans up private and public keystore thus only needs to be done once.
     * Subsequent C_InitToken calls will delete any existing keys within the keystores
     */
    rc= funcs->C_InitToken(0, soPin, strlen((const char *) soPin), tokenNameBuf);
    if (rc != CKR_OK) {
        printf("error C_InitToken: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    printf("Opening a session... \n");
    rc = funcs->C_OpenSession( 0, flags, (CK_VOID_PTR) NULL, NULL, &session );
    if (rc != CKR_OK) {
        printf("error C_OpenSession: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Logging in as normal user... \n");
    rc = funcs->C_Login( session, CKU_USER, userPin, strlen((const char *) userPin));
    if (rc != CKR_OK) {
        printf("error C_Login: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Generating ED25519 public object... \n");
    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_ECDSA;
    CK_BYTE curve_oid[] = {0x06, 0x03, 0x2b, 0x65, 0x70};
    CK_BYTE ec_point[] = {0x05, 0x53, 0xbc, 0xb2, 0xd0, 0x27, 0x28, 0x56, 0x53, 0x12, 0x2c, 0xe2, 0x96, 0x1e, 0xc7, 0xaa, 0x62, 0x9e, 0xd2, 0x38, 0x0c, 0x34, 0xbb, 0x00, 0xfe, 0x37, 0xbf, 0xd1, 0x21, 0x93, 0x7c, 0xbd}; 
    CK_ATTRIBUTE pub_tmpl[] = {
        {CKA_TOKEN,        &isTrue,     sizeof(isTrue) },
        {CKA_CLASS,        &objClass,   sizeof(objClass) },
        {CKA_KEY_TYPE,     &keyType,    sizeof(keyType) },
        {CKA_PRIVATE,      &isFalse,    sizeof(isFalse) },
        {CKA_VERIFY,       &isTrue,     sizeof(isTrue) },
        {CKA_EC_PARAMS,    &curve_oid,  sizeof(curve_oid) },
        {CKA_EC_POINT,     &ec_point,   sizeof(ec_point) },
    };

    rc = funcs->C_CreateObject(session, pub_tmpl, sizeof(pub_tmpl)/sizeof(CK_ATTRIBUTE), &pubObject);
    if (rc != CKR_OK) {
        printf("error C_CreateObject: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Logging out... \n");
    rc = funcs->C_Logout(session);
    if (rc != CKR_OK) {
        printf("error C_Logout: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Closing the session... \n");
    rc = funcs->C_CloseSession( session );
    if (rc != CKR_OK) {
        printf("error C_CloseSession: rc=0x%04lx\n", rc );
        return !CKR_OK;
    }

    printf("Finalizing... \n");
    rc = funcs->C_Finalize( NULL );
    if (rc != CKR_OK) {
        printf("error C_Finalize: rc=0x%04lx\n", rc );
        return !CKR_OK;
    }
    printf("Sample completed successfully!\n");
    return 0;
}
