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
    
    if (Nbytes > 0) {
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
+ (NSData *)sha256:(NSData *)data {
    
    if (data == nil) {
        return data;
    }
    
    NSMutableData *digest = [[NSMutableData alloc] initWithLength:CC_SHA256_DIGEST_LENGTH];
    (void) CC_SHA256(data.bytes, (CC_LONG) data.length, digest.mutableBytes);
    
    return digest;
}
+ (NSData *)sha:(NSData *)data
          nbits:(NSInteger)nbits {
    
    if (data == nil) {
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
    
    if (data == nil || key == nil) {
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

+ (NSUInteger)KDFRoundsForDerivationTime:(uint32_t)ms
                             passwordLen:(size_t)passwordLen
                              saltLength:(size_t)saltLen
                             ccAlgorithm:(CCPseudoRandomAlgorithm)ccAlgorithm
                        derivedKeyLength:(size_t)keyLen{
    int result;
    uint32_t derivationTimeMilliseconds = ms;
    
    if (ms == 0 || ms > UINT32_MAX) {
        derivationTimeMilliseconds = 1000;  // 1 second
    }
    
    if (saltLen == 0 || passwordLen == 0) {
        return 0;
    }
    
    // Do the key derivation.
    result = (int) CCCalibratePBKDF(kCCPBKDF2,
                                    passwordLen,
                                    saltLen,
                                    ccAlgorithm,
                                    keyLen,
                                    (uint32_t)derivationTimeMilliseconds
                                    );
    
    return (NSUInteger)result;
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
    
    NSInteger nbits = key.length * 8;

    NSMutableData *Ki = [[NSMutableData alloc] initWithData:iv];
    [Ki appendData:[[self sha256:key] subdataWithRange:NSMakeRange(kCCBlockSizeAES128, kCCBlockSizeAES128)]];
    
    NSData *digest = [self HMAC:[self sha256:encryptedData]
                            key:Ki
                          nbits:nbits];
    
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
    NSInteger nbits = len * 8;

    NSData *mac = [data subdataWithRange:NSMakeRange(0, len)];
    NSData *encryptedData = [data subdataWithRange:NSMakeRange(len, data.length - len)];
    
    NSMutableData *Ki = [[NSMutableData alloc] initWithData:iv];
    [Ki appendData:[[self sha256:key] subdataWithRange:NSMakeRange(kCCBlockSizeAES128, kCCBlockSizeAES128)]];
    
    NSData *digestToCheck = [self HMAC:[self sha256:encryptedData]
                                   key:Ki
                                 nbits:nbits];

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
        
        NSInteger mbytes = 32;
        
        // 2 x 32 x 32 bytes of private hash values
        NSMutableArray *priv_left = [[NSMutableArray alloc] initWithCapacity:mbytes];
        NSMutableArray *priv_right = [[NSMutableArray alloc] initWithCapacity:mbytes];
        
        // 2 x 32 x 32 bytes of hashed private arrays
        NSMutableArray *pub_left = [[NSMutableArray alloc] initWithCapacity:mbytes];
        NSMutableArray *pub_right = [[NSMutableArray alloc] initWithCapacity:mbytes];
        NSMutableArray *pub = [[NSMutableArray alloc] initWithCapacity:2*mbytes];
        
        // convert the digest of the message (message hash) into its binary form
        NSString *digestBinary = [DataFormatter hexToBinary:[DataFormatter hexDataToString:digest]];
        
        // populate arrays of hashes
        for (NSInteger i = 0; i < digestBinary.length; i++) {
            NSData *saltL = [Crypto generateRandomCrytoBytes:mbytes];
            NSData *saltR = [Crypto generateRandomCrytoBytes:mbytes];
            [priv_left addObject:saltL];
            [priv_right addObject:saltR];
            
            // hash each of the private hashes for the corresponding public hash values
            NSData *pubsaltL = [Crypto sha256:saltL];
            NSData *pubsaltR = [Crypto sha256:saltR];
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
        
        return sig;
    }
}

/**  ------------------------------------------------------------
 //  Example Proof of Work Algorithm
 //  ------------------------------------------------------------
 */
+ (NSDictionary *)proofOfWork:(NSData *)challenge difficulty:(NSInteger)diff {
    
    if (challenge == nil || diff == 0) {
        return nil;
    }
    
    // init vars
    NSString *zeros = @"00000000000000000000000000000000";
    NSData *hash = [DataFormatter hexStringToData:@"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"];
    
    // range of leading 0's to find
    NSRange range = NSMakeRange(0, diff);
    zeros = [zeros substringWithRange:range];
    
    NSInteger nonce = 0;
    BOOL proceed = YES;
    
    // do work
    while (proceed) {
        @autoreleasepool {
            NSMutableData *input = [[NSMutableData alloc] initWithData:challenge];
            // hash challenge with concatenated nonce
            [input appendData:[DataFormatter hexStringToData:[DataFormatter hexFromInt:nonce]]];
            hash = [self sha256:input];
            
            // check if valid
            if ([[DataFormatter hexDataToString:[hash subdataWithRange:range]] substringToIndex:diff] == zeros) {
                // return dictionary of valid proof parameters
                NSMutableDictionary *dict = [[NSMutableDictionary alloc] initWithCapacity:2];
                [dict setObject:hash forKey:@"proof"];
                [dict setObject:[NSNumber numberWithInteger:nonce] forKey:@"nonce"];

                return dict;
            }
            // check overflow
            if (nonce++ >= kMaxNonce) {
                proceed = NO;
            }
        }
    }
    
    return nil;
}

@end
