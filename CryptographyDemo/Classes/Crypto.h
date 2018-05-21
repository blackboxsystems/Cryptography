//
//  Crypto.h
//  CryptographyDemo
//
//  Created by Hello World on 5/15/18.
//  Copyright © 2018 blackboxsystems. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import "DataFormatter.h"


// key derivation rounds
static const NSInteger kPBKDFRoundsAES = 4096;

@interface Crypto : NSObject


// cryptographically secure random bytes
+ (NSData *)generateRandomCrytoBytes:(size_t )Nbytes;

// SHA hash
+ (NSData *)SHA:(NSData *)data
          nbits:(NSInteger)nbytes;

// Hashed Message Authentication Code
+ (NSData *)HMAC:(NSData *)data
             key:(NSData *)key
           nbits:(NSInteger)digestSize;

// key derivation
+ (NSData *)deriveKey:(NSString *)password
                 salt:(NSData *)salt
               rounds:(NSInteger)rounds
                  prf:(CCPseudoRandomAlgorithm)prf;

// wrapper for encryption
+ (NSData *)encrypt:(NSData *)data
                key:(NSData *)key
                 iv:(NSData *)iv;

// wrapper for decryption
+ (NSData *)decrypt:(NSData *)data
                key:(NSData *)key
                 iv:(NSData *)iv;

// encrypt-then-mac
+ (NSData *)encryptThenMAC:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv;

// check mac then decrypt
+ (NSData *)decryptWithMAC:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv;

// symmetric key encryption
+ (NSData *)doCipher:(NSData *)plainText
                 key:(NSData *)symmetricKey
             context:(CCOperation)encryptOrDecrypt
                mode:(CCMode)mode
             padding:(CCOptions *)pkcs7
                  iv:(NSData *)iv;

// xor operation
+ (NSData *)xorData:(NSData *)data1
           withData:(NSData *)data2;

// lamport signature generation
+ (NSData *)generateLamportSignature:(NSData *)digest;


@end
