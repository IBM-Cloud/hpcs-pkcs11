# Overview

IBM Cloud® Hyper Protect Crypto Services is a dedicated key management service and hardware security module (HSM). This service allows you to take ownership of a cloud HSM to fully manage your encryption keys and to perform cryptographic operations. Hyper Protect Crypto Services is also the only service in the cloud industry that is built on FIPS 140-2 Level 4-certified hardware.

# Installing the PCKS #11 files

The files contained in this repository allow clients to access a cloud HSM via the HPCS service using a PKCS #11 library and its associated configuration file. The files are categorized by *releases*, which can be accessed from the hpcs-pkcs11 repository's [releases URL](https://github.com/IBM-Cloud/hpcs-pkcs11/releases).

**NOTE:** The PKCS #11 library, for both the amd64 and s390x platforms, is currently supported only on Linux.

There are two files used along with your PKCS #11 application:
1. The PKCS #11 library:  pkcs11-grep11-**platform**.so.**major.minor.build**

   - **platform** is amd64 or s390x
  
   - **major.minor.build** refers to the version of the library

   - **NOTE:** Refer to step 1 of the IBM Cloud HPCS documentation topic, [Set up the PKCS #11 library](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-set-up-pkcs-api), for instructions on where to place the PKCS #11 library file.

2. The PKCS #11 client configuration file: *grep11client.yaml*
   - Before you update the configuration file, PKCS #11 users must first be set up. Follow the steps outlined in the IBM Cloud Hyper Protect Crypto Services documentation topic, [Best practices for setting up PKCS #11 user types](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-best-practice-pkcs11-access#step2-create-service-id-api-key), to complete the PKCS #11 user setup tasks.

   - Changes to the configuration file are needed after you download it. Update the *grep11client.yaml* configuration file by following step 3 of the IBM Cloud Hyper Protect Crypto Services documentation topic: [Set up the PKCS #11 configuration file](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-set-up-pkcs-api)

   - **NOTE:** The *grep11client.yaml* configuration file must be moved into the same directory as the PKCS #11 library or in the directory `/etc/ep11client`.

## Verify the integrity and authenticity of the PKCS #11 library

For maximum security, you can optionally verify the integrity and authenticity of the PKCS #11 library. Hyper Protect Crypto Services enable [signed code verification](https://en.wikipedia.org/wiki/Code_signing) to ensure that the signature matches the original code. If the downloaded PKCS #11 library file is altered or corrupted, a different signature is produced and the verification fails. To make sure the files are not tampered with or corrupted during the download process, complete the following steps by using the [OpenSSL command-line tool](https://wiki.openssl.org/index.php/Binaries).

1. Download the latest version of the following files from the hpcs-pkcs11 repository's [releases URL](https://github.com/IBM-Cloud/hpcs-pkcs11/releases) to the same directory where you store the PKCS #11 library:

    - `pkcs11-grep11-<platform>.so.<version>.sig`: The signed cryptographic hash of the PKCS #11 library, where **platform** is either *amd64* or *s390x*  and **version** is the major.minor.build (e.g., 2.3.4) of the signature file. Both **platform** and **version** must match the respective **platform** and **version** of the PKCS #11 library that is used.

    - `signing_cert.pem`: The signing certificate for the HPCS PKCS #11 files.
    
    - `digicert_cert.pem`: An intermediate code signing certificate to prove the Hyper Protect Crypto Services PKCS #11 files signing certificate.

2. Extract the public key from the signing certificate `signing_cert.pem` to the `sigkey.pub` file with the following command by using the OpenSSL command-line tool:

   `openssl x509 -pubkey -noout -in signing_cert.pem -out sigkey.pub`

3. Verify the integrity of the PKCS #11 library file with the following command:

   `openssl dgst -sha256 -verify sigkey.pub -signature pkcs11-grep11-<platform>.so.<version>.sig pkcs11-grep11-<platform>.so.<version>`

   **NOTE:** Replace **platform** with either *amd64* or *s390x* and replace **version** with the major.minor.build (e.g., 2.3.4) of the library.

   When the verification is successful, `Verified OK` is displayed.

4. Verify the authenticity and validity of the signing certificate with the following command:

   `openssl ocsp -no_nonce -issuer digicert_cert.pem -cert signing_cert.pem -VAfile digicert_cert.pem -text -url http://ocsp.digicert.com -respout ocsptest`

   When the verification is successful, `Response verify OK` and `signing_cert.pem: good` are displayed in the output.

5. If the verification fails, cancel the installation and contact [IBM for support](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-getting-help).
