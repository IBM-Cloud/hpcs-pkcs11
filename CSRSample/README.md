# HPCS PKCS11 CSR Generator Sample

## Description
This README document provides a comprehensive guide for the "HPCS PKCS11 CSR Generator" written in Go (Golang). This program is designed to interact with IBM Cloud Hyper Protect Crypto Services (HPCS) using the PKCS#11 interface to generate a Certificate Signing Request (CSR).

## Prerequisites
* Go programming environment
* Access to an IBM Cloud HPCS instance
* PKCS#11 library (grep11-pkcs11.so)
  * Ensure that the PKCS#11 library path is correctly configured in your environment.

## Configuration
Edit the following variables in main.go as needed:

* NORMAL_APIKEY: The HPCS API Key for accessing HPCS instance.
* PKCS11_LIBARY_PATH: Path to the PKCS#11 library.
* KEY_TYPE: The key type for CSR ECDSA(P-224, P-256, P-384, P-521), ED25519, or RSA.
* EXISTING_KEY: true to use an existing key pair, false to generate a new one.
* PUBLIC_CKA_LABEL & PRIVATE_CKA_LABEL: Labels for the public and private keys.
* CSR Information (CommonName, Country, etc.).

## Run the program:
> go run main.go

A CSR will be generated and saved as csr.pem in the current directory.