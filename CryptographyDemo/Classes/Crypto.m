//
//  Crypto.m
//  CryptographyDemo
//
//  Created by Hello World on 5/15/18.
//  Copyright © 2018 blackboxsystems. All rights reserved.
//

#import "Crypto.h"


@implementation Crypto


/**  ------------------------------------------------------------
 //  Randomization
 //
 //  - Cryptographically Secure Random Byte Generation
 //  ------------------------------------------------------------
 */
+ (NSData *)generateRandomCrytoBytes:(size_t )Nbytes {
    
    NSData *byteData = nil;
    
    if ((Nbytes > 0) && (Nbytes % 8 == 0)) {
        uint8_t *bytes = malloc(Nbytes);
        int status = SecRandomCopyBytes(kSecRandomDefault, Nbytes, bytes);
        if (status != 0) {
            return nil;
        }
        byteData = [NSData dataWithBytes:bytes length:Nbytes];
        free(bytes);
    }
    return byteData;
}

/**  ------------------------------------------------------------
 //  SHA Hash Function
 //  ------------------------------------------------------------
 */
+ (NSData *)SHA:(NSData *)data
          nbits:(NSInteger)nbits {
    
    if (data == nil || (nbits % 8 != 0)) {
        return nil;
    }
    
    NSMutableData *digest;
    
    switch (nbits) {
        case 224:
            digest = [[NSMutableData alloc] initWithLength:CC_SHA224_DIGEST_LENGTH];
            (void) CC_SHA224(data.bytes, (CC_LONG) data.length, digest.mutableBytes);
            break;
        case 256:
            digest = [[NSMutableData alloc] initWithLength:CC_SHA256_DIGEST_LENGTH];
            (void) CC_SHA256(data.bytes, (CC_LONG) data.length, digest.mutableBytes);
            break;
        case 384:
            digest = [[NSMutableData alloc] initWithLength:CC_SHA384_DIGEST_LENGTH];
            (void) CC_SHA384(data.bytes, (CC_LONG) data.length, digest.mutableBytes);
            break;
        case 512:
            digest = [[NSMutableData alloc] initWithLength:CC_SHA512_DIGEST_LENGTH];
            (void) CC_SHA512(data.bytes, (CC_LONG) data.length, digest.mutableBytes);
            break;
        default:
            digest = [[NSMutableData alloc] initWithLength:CC_SHA256_DIGEST_LENGTH];
            (void) CC_SHA256(data.bytes, (CC_LONG) data.length, digest.mutableBytes);
            break;
    }
    
    return digest;
}

/**  ------------------------------------------------------------
 //  Hashed Message Authentication Code
 //  ------------------------------------------------------------
 */
+ (NSData *)HMAC:(NSData *)data
             key:(NSData *)key
           nbits:(NSInteger)nbits {
    
    if (data == nil || key == nil || nbits % 8 != 0) {
        return nil;
    }
    
    NSMutableData *hmac;
    
    switch (nbits){
        case 224:
            hmac = [[NSMutableData alloc] initWithLength:CC_SHA224_DIGEST_LENGTH];
            CCHmac(kCCHmacAlgSHA224, key.bytes, key.length, data.bytes, data.length, hmac.mutableBytes);
            break;
        case 256:
            hmac = [[NSMutableData alloc] initWithLength:CC_SHA256_DIGEST_LENGTH];
            CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, data.bytes, data.length, hmac.mutableBytes);
            break;
        case 384:
            hmac = [[NSMutableData alloc] initWithLength:CC_SHA384_DIGEST_LENGTH];
            CCHmac(kCCHmacAlgSHA384, key.bytes, key.length, data.bytes, data.length, hmac.mutableBytes);
            break;
        case 512:
            hmac = [[NSMutableData alloc] initWithLength:CC_SHA512_DIGEST_LENGTH];
            CCHmac(kCCHmacAlgSHA512, key.bytes, key.length, data.bytes, data.length, hmac.mutableBytes);
            break;
        default:
            hmac = [[NSMutableData alloc] initWithLength:CC_SHA256_DIGEST_LENGTH];
            CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, data.bytes, data.length, hmac.mutableBytes);
            break;
    }
    
    return hmac;
}

/**  ------------------------------------------------------------
 //  Key Derivation
 //  ------------------------------------------------------------
 */
+ (NSData *)deriveKey:(NSString *)password
                 salt:(NSData *)salt
               rounds:(NSInteger)rounds
                  prf:(CCPseudoRandomAlgorithm)prf {
    
    if (salt == nil || password == nil) {
        return nil;
    }
    
    NSMutableData *derivedKey = [NSMutableData dataWithLength:salt.length];
    
    (void)CCKeyDerivationPBKDF(kCCPBKDF2,                // algorithm
                               password.UTF8String,      // password
                               password.length,          // password length
                               salt.bytes,               // salt bytes
                               salt.length,              // salt length
                               prf,                      // PRF (HMAC-SHA512/HMAC-SHA256)
                               (unsigned int)rounds,     // number of rounds
                               derivedKey.mutableBytes,  // derived key
                               derivedKey.length);       // derived key length
    
    return derivedKey;
}

/**  ------------------------------------------------------------
 //  Encryption/Decryption
 //  ------------------------------------------------------------
 */
+ (NSData *)encrypt:(NSData *)data
                key:(NSData *)key
                 iv:(NSData *)iv {
    
    if (data == nil || key == nil) {
        return nil;
    }
    
    CCOptions padding = 0;
    NSData *encryptedData = [self doCipher:data
                                       key:key
                                   context:kCCEncrypt
                                      mode:kCCModeCTR
                                   padding:&padding
                                        iv:iv];

    return encryptedData;
}
+ (NSData *)decrypt:(NSData *)data
                key:(NSData *)key
                 iv:(NSData *)iv {
    
    if (data == nil || key == nil) {
        return nil;
    }
    
    CCOptions padding = 0;
    NSData *decryptedData = [self doCipher:data
                                       key:key
                                   context:kCCDecrypt
                                      mode:kCCModeCTR
                                   padding:&padding
                                        iv:iv];
    
    return decryptedData;
}

/**  ------------------------------------------------------------
 //  Encryption with HMAC (Authenticated)
 //  ------------------------------------------------------------
 */
+ (NSData *)encryptThenMAC:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv {
    
    if (key == nil || data == nil) {
        return nil;
    }
    
    // initialization vector
    if (iv == nil) {
        iv = [Crypto generateRandomCrytoBytes:kCCBlockSizeAES128];
    }
    
    // encrypt
    NSData *encryptedData = [self encrypt:data key:key iv:iv];
    
    if (encryptedData == nil) {
        return nil;
    }
    
    NSMutableData *Ki = [[NSMutableData alloc] initWithData:iv];
    [Ki appendData:[[self SHA:key nbits:256] subdataWithRange:NSMakeRange(kCCBlockSizeAES128, kCCBlockSizeAES128)]];
    
    NSData *digest = [self HMAC:[self SHA:encryptedData nbits:key.length]
                            key:Ki
                          nbits:key.length];
    
    // append encrypted data to hmac
    NSMutableData *mutableData = [[NSMutableData alloc] initWithData:digest];
    [mutableData appendData:encryptedData];
    
    return mutableData;
}
+ (NSData *)decryptWithMAC:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv {
    
    if (data == nil || key == nil || iv == nil) {
        return nil;
    }
    
    NSInteger len = key.length;
    NSData *mac = [data subdataWithRange:NSMakeRange(0, len)];
    NSData *encryptedData = [data subdataWithRange:NSMakeRange(len, data.length - len)];
    
    NSMutableData *Ki = [[NSMutableData alloc] initWithData:iv];
    [Ki appendData:[[self SHA:key nbits:256] subdataWithRange:NSMakeRange(kCCBlockSizeAES128, kCCBlockSizeAES128)]];
    
    NSData *digestToCheck = [self HMAC:[self SHA:encryptedData nbits:key.length]
                                   key:Ki
                                 nbits:key.length];

    // integrity check
    if ([digestToCheck isEqualToData:mac]) {
        NSData *decryptedData = [self decrypt:encryptedData key:key iv:iv];
        return decryptedData;
    }
    
    return nil;
}


/**  ------------------------------------------------------------
 //  Symmetric AES Cipher Operation
 //  - note: iv parameter is ignored if ECB mode or if a stream cipher algorithm is selected.
 //  Modes:
 //  - ECB should not be used if encrypting more than one block of data with the same key.
 //  - CBC, OFB and CFB are similar, however OFB/CFB is better because you only need encryption and not decryption, which can save code space.
 //  - CTR is used if you want good parallelization (ie. speed), instead of CBC/OFB/CFB.
 //  ------------------------------------------------------------
 */
+ (NSData *)doCipher:(NSData *)plainText
                 key:(NSData *)key
             context:(CCOperation)encryptOrDecrypt
                mode:(CCMode)mode
             padding:(CCOptions *)padding
                  iv:(NSData *)iv {
    
    if ((plainText != nil) && (key != nil)) {
        CCCryptorStatus ccStatus = kCCSuccess;
        CCCryptorRef cryptor = nil;
        NSData *data = nil;
        uint8_t *bufferPtr = nil;
        size_t bufferPtrSize = 0;
        size_t remainingBytes = 0;
        size_t movedBytes = 0;
        size_t plainTextBufferSize = 0;
        size_t totalBytesWritten = 0;
        uint8_t *ptr;
        
        plainTextBufferSize = [plainText length];
        
        if (encryptOrDecrypt == kCCEncrypt) {
            if (*padding != kCCOptionECBMode) {
                if ((plainTextBufferSize % kCCBlockSizeAES128) == 0) {
                    *padding = 0x0000;
                } else {
                    *padding = kCCOptionPKCS7Padding;
                }
            }
        }
        
        // Initialization vector, create one if nil
        if (iv == nil) {
            iv = [self generateRandomCrytoBytes:kCCBlockSizeAES128];
        }
        
        switch (mode) {
            case kCCModeECB:
                ccStatus = CCCryptorCreate(encryptOrDecrypt,
                                           kCCAlgorithmAES,
                                           *padding,
                                           (const void *)[key bytes],
                                           kCCKeySizeAES256,
                                           (__bridge const void *)iv,
                                           &cryptor
                                           );
                break;
            case kCCModeCTR:
                ccStatus = CCCryptorCreateWithMode(encryptOrDecrypt,
                                                   kCCModeCTR,
                                                   kCCAlgorithmAES,
                                                   *padding,
                                                   iv.bytes,
                                                   key.bytes,
                                                   key.length,
                                                   NULL,
                                                   0,
                                                   0,
                                                   kCCModeOptionCTR_BE,
                                                   &cryptor
                                                   );
                break;
            case kCCModeCBC:
                ccStatus = CCCryptorCreateWithMode(encryptOrDecrypt,
                                                   kCCModeCBC,
                                                   kCCAlgorithmAES,
                                                   *padding,
                                                   iv.bytes,
                                                   key.bytes,
                                                   key.length,
                                                   NULL,
                                                   0,
                                                   0,
                                                   0,
                                                   &cryptor
                                                   );
                break;
            case kCCModeCFB:
                ccStatus = CCCryptorCreateWithMode(encryptOrDecrypt,
                                                   kCCModeCFB,
                                                   kCCAlgorithmAES,
                                                   *padding,
                                                   iv.bytes,
                                                   key.bytes,
                                                   key.length,
                                                   NULL,
                                                   0,
                                                   0,
                                                   0,
                                                   &cryptor
                                                   );
                break;
            default:
                ccStatus = CCCryptorCreate(encryptOrDecrypt,
                                           kCCAlgorithmAES,
                                           *padding,
                                           (const void *)[key bytes],
                                           kCCKeySizeAES256,
                                           (__bridge const void *)iv,
                                           &cryptor
                                           );
                break;
        }
        
        if (ccStatus == kCCSuccess) {
            // Calculate byte block alignment for all calls through to and including final.
            bufferPtrSize = CCCryptorGetOutputLength(cryptor, plainTextBufferSize, true);
            
            // Allocate buffer.
            bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t) );
            // Zero out buffer.
            memset((void *)bufferPtr, 0x0, bufferPtrSize);
            
            // Initialize some necessary book keeping.
            ptr = bufferPtr;
            remainingBytes = bufferPtrSize;
            
            // perform the encryption or decryption.
            ccStatus = CCCryptorUpdate(cryptor,
                                       (const void *)[plainText bytes],
                                       plainTextBufferSize,
                                       ptr,
                                       remainingBytes,
                                       &movedBytes
                                       );
            
            if (ccStatus == kCCSuccess) {
                // Handle bytes
                ptr += movedBytes;
                remainingBytes -= movedBytes;
                totalBytesWritten += movedBytes;
                
                // Finalize everything to the output buffer.
                ccStatus = CCCryptorFinal(cryptor,
                                          ptr,
                                          remainingBytes,
                                          &movedBytes
                                          );
                
                totalBytesWritten += movedBytes;
                
                if (cryptor) {
                    (void) CCCryptorRelease(cryptor);
                    cryptor = nil;
                }
                
                if (ccStatus == kCCSuccess) {
                    data = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)totalBytesWritten];

                    if (bufferPtr) {
                        free(bufferPtr);
                    }
                    
                    return data;
                }
            }
        }
    }
    
    return nil;
}

/**  ------------------------------------------------------------
 //  XOR Operation
 //  ------------------------------------------------------------
 */
+ (NSData *)xorData:(NSData *)data1
           withData:(NSData *)data2{
    
    if ((data1 == nil) || (data2 == nil)) {
        return (data1 == nil ? data2 : data1);
    }
    
    NSMutableData *xorData = [[NSMutableData alloc] init];
    const char *data1Bytes = [data1 bytes];
    const char *data2Bytes = [data2 bytes];
    int L1 = (int)data1.length;
    int L2 = (int)data2.length;
    
    for (int i = 0; i < (L1 > L2 ? L2 : L1); i++){
        const char xorByte = data1Bytes[i] ^ data2Bytes[i];
        [xorData appendBytes:&xorByte length:1];
    }
    
    return xorData;
}

/**  ------------------------------------------------------------
 //  Lamport Signature Scheme
 //  ------------------------------------------------------------
 */
+ (NSData *)generateLamportSignature:(NSData *)digest {
    
    @autoreleasepool {
        // 2 x 256 x 256 bits of private hash values
        NSMutableArray *priv_left = [[NSMutableArray alloc] initWithCapacity:256];
        NSMutableArray *priv_right = [[NSMutableArray alloc] initWithCapacity:256];
        
        // 2 x 256 x 256 bits of hashed private arrays
        NSMutableArray *pub_left = [[NSMutableArray alloc] initWithCapacity:256];
        NSMutableArray *pub_right = [[NSMutableArray alloc] initWithCapacity:256];
        NSMutableArray *pub = [[NSMutableArray alloc] initWithCapacity:512];
        
        // convert the digest of the message (message hash) into its binary form
        NSString *digestBinary = [DataFormatter hexToBinary:[DataFormatter hexDataToString:digest]];
        
        NSInteger mbytes = 32;
        NSInteger mbits = 8 * mbytes;
        
        // populate arrays of hashes
        for (NSInteger i = 0; i < digestBinary.length; i++) {
            NSData *saltL = [Crypto generateRandomCrytoBytes:mbytes];
            NSData *saltR = [Crypto generateRandomCrytoBytes:mbytes];
            [priv_left addObject:saltL];
            [priv_right addObject:saltR];
            
            // hash each of the private hashes for the corresponding public hash values
            NSData *pubsaltL = [Crypto SHA:saltL nbits:mbits];
            NSData *pubsaltR = [Crypto SHA:saltR nbits:mbits];
            [pub_left addObject:pubsaltL];
            [pub_right addObject:pubsaltR];
        }
        
        [pub addObject:pub_left];
        [pub addObject:pub_right];

        NSMutableData *sig = [[NSMutableData alloc] initWithCapacity:256];
        
        // generate 256 x 256 bit signature
        // for each bit in the hash, based on the value of the bit, we pick one number
        // from the corresponding pairs of numbers that comprise the private key
        for (NSInteger j = 0; j < digestBinary.length; j++) {
            NSString *bite = [digestBinary substringWithRange:NSMakeRange(j, 1)];
            if ([bite isEqualToString:@"1"]) {
                [sig appendData:[priv_left objectAtIndex:j]];
            } else {
                [sig appendData:[priv_right objectAtIndex:j]];
            }
        }
        
//        NSData *condensed_signature = [Crypto SHA:sig nbits:mbits];
        return sig;
    }
}


@end
