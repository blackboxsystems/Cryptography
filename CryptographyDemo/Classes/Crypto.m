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
+ (NSData *)hmac:(NSData *)data
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
#pragma mark - Password-Based Key Derivation (PBKDF2)
+ (NSData *)deriveKey:(NSString *)password
                 salt:(NSData *)salt
                 mode:(BBKeyDerivationMode)mode
               rounds:(NSInteger)rounds{
    
    NSMutableData *derivedKey = [NSMutableData dataWithLength:(mode == BBDeriveKEY ? 64 :
                                                               (mode == BBDeriveAES ? 32 : salt.length))];
    
    CCPseudoRandomAlgorithm prf = (salt.length == 28 ? kCCPRFHmacAlgSHA224 :
                                   (salt.length == 32 ? kCCPRFHmacAlgSHA256 :
                                    (salt.length == 36 ? kCCPRFHmacAlgSHA384 : kCCPRFHmacAlgSHA512)));
    if (password.length == 0 || rounds == 0) {
        return nil;
    }
    
    int result = 0;
    switch (mode) {
            // passphrase derived key
        case BBDeriveKEY:
            result = CCKeyDerivationPBKDF(kCCPBKDF2,                // algorithm
                                          password.UTF8String,      // password
                                          password.length,          // password length
                                          salt.bytes,               // salt bytes
                                          salt.length,              // salt length
                                          kCCPRFHmacAlgSHA512,      // PRF
                                          (unsigned int)rounds,     // rounds
                                          derivedKey.mutableBytes,  // derivedKey
                                          derivedKey.length);       // derivedKeyLen
            break;
            
            // secure enclave device biometry key
        case BBDeriveAES:
            result = CCKeyDerivationPBKDF(kCCPBKDF2,
                                          password.UTF8String,
                                          password.length,
                                          salt.bytes,
                                          salt.length,
                                          kCCPRFHmacAlgSHA256,
                                          (unsigned int)rounds,
                                          derivedKey.mutableBytes,
                                          derivedKey.length);
            break;
        default:
            result = CCKeyDerivationPBKDF(kCCPBKDF2,
                                          password.UTF8String,
                                          password.length,
                                          salt.bytes,
                                          salt.length,
                                          prf,
                                          (unsigned int)rounds,
                                          derivedKey.mutableBytes,
                                          derivedKey.length);
            break;
    }
    
    if (result != kCCSuccess) {
        return nil;
    }
    
    return derivedKey;
}

// calculate number of rounds for time of PBKDF2 derivation
+ (NSUInteger)KDFRoundsForDerivationTime:(double)ms
                          passwordLength:(size_t)passwordLength
                              saltLength:(size_t)saltLength
                             ccAlgorithm:(CCPseudoRandomAlgorithm)ccAlgorithm
                        derivedKeyLength:(size_t)keyLength{
    
    int result;
    double derivationTimeMilliseconds = ms;
    
    if (saltLength == 0) {
        return 0;
    }
    
    // key derivation round calculation
    result = (int)CCCalibratePBKDF(kCCPBKDF2,
                                   passwordLength,
                                   saltLength,
                                   ccAlgorithm,
                                   keyLength,
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
                                 algorithm:kCCAlgorithmAES
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
                                 algorithm:kCCAlgorithmAES
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
    CCOptions padding = 0;
    NSData *encryptedData = [self doCipher:data
                                       key:key
                                   context:kCCEncrypt
                                      mode:kCCModeCTR
                                 algorithm:kCCAlgorithmAES
                                   padding:&padding
                                        iv:iv];

    if (encryptedData == nil) {
        return nil;
    }
    
    NSInteger nbits = key.length * 8;

    NSMutableData *Ki = [[NSMutableData alloc] initWithData:iv];
    [Ki appendData:[[self sha256:key] subdataWithRange:NSMakeRange(kCCBlockSizeAES128, kCCBlockSizeAES128)]];
    
    NSData *digest = [self hmac:[self sha256:encryptedData]
                            key:Ki
                          nbits:nbits];
    
    // append encrypted data to hmac
    NSMutableData *mutableData = [[NSMutableData alloc] initWithData:digest];
    [mutableData appendData:encryptedData];
    
    return mutableData;
}
#pragma mark - CHECK-MAC-THEN-DECRYPT
+ (NSData * _Nullable)decryptWithMAC:(NSData *)data
                              intKey:(NSData *)Ky
                              encKey:(NSData *)Kx{
    
    // lengths of bytes to parse out
    NSInteger key_length = Kx.length;
    NSInteger param_length = kAES256_IV_LENGTH + key_length;
    
    if (data.length <= param_length) {
        return nil;
    }
    
    // parse iv, hmac, and encrypted blob
    NSData *iv = [data subdataWithRange:NSMakeRange(0, kAES256_IV_LENGTH)];
    NSData *hmac = [data subdataWithRange:NSMakeRange(kAES256_IV_LENGTH, key_length)];
    NSData *blob = [data subdataWithRange:NSMakeRange(param_length, data.length - param_length)];
    
    // form integrity key
    NSMutableData *macKey = [[NSMutableData alloc] initWithData:Ky];
    [macKey appendData:iv];
    
    // generate HMAC
    NSData *digest = [Crypto hmac:[Crypto sha256:blob]
                              key:[Crypto sha256:macKey]
                            nbits:(key_length * 8)];
    
    // check the HMAC and if integrity fails we should not trust the underlying data
    if (![digest isEqualToData:hmac]) {
        return nil;
    }
    
    // decrypt data
    CCOptions pad = 0;
    NSData *decryptedData = [Crypto doCipher:blob
                                         key:Kx
                                     context:kCCDecrypt
                                        mode:kCCModeCTR
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    return decryptedData;
}


+ (NSData *)getIV:(NSInteger)nbytes{
    return [[Crypto sha256:[self generateRandomCrytoBytes:nbytes]] subdataWithRange:NSMakeRange(0, nbytes)];
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
#pragma mark - SYMMETRIC ENCRYPTION
+ (NSData *)doCipher:(NSData *)plainText
                 key:(NSData *)key
             context:(CCOperation)encryptOrDecrypt
                mode:(CCMode)mode
           algorithm:(CCAlgorithm)algo
             padding:(CCOptions *)padding
                  iv:(NSData *)iv{
    
    if ((plainText != NULL) && (key != NULL))
    {
        CCCryptorStatus ccStatus = kCCSuccess;
        CCCryptorRef cryptor = NULL;
        NSData *data = nil;
        uint8_t *bufferPtr = NULL;
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
            } else if (mode == kCCModeECB) {
                if ((plainTextBufferSize % kCCBlockSizeAES128) == 0) {
                    *padding = 0x0000;
                }
            }
        }
        
        // Initialization vector
        if (iv == nil && mode != kCCModeECB) {
            iv = [self getIV:kCCBlockSizeAES128];
        }
        
        switch (mode) {
            case kCCModeECB:
                ccStatus = CCCryptorCreateWithMode(encryptOrDecrypt,
                                                   kCCModeECB,
                                                   algo,
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
            case kCCModeCTR:
                ccStatus = CCCryptorCreateWithMode(encryptOrDecrypt,
                                                   kCCModeCTR,
                                                   algo,
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
                // needs iv
                ccStatus = CCCryptorCreateWithMode(encryptOrDecrypt,
                                                   kCCModeCBC,
                                                   algo,
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
                // needs iv
                ccStatus = CCCryptorCreateWithMode(encryptOrDecrypt,
                                                   kCCModeCFB,
                                                   algo,
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
            case kCCModeOFB:
                // needs iv
                ccStatus = CCCryptorCreateWithMode(encryptOrDecrypt,
                                                   kCCModeOFB,
                                                   algo,
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
                ccStatus = CCCryptorCreateWithMode(encryptOrDecrypt,
                                                   kCCModeCTR,
                                                   algo,
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
        }
        
        if (ccStatus == kCCSuccess)
        {
            // calculate byte block alignment for all calls through to and including final.
            bufferPtrSize = CCCryptorGetOutputLength(cryptor, plainTextBufferSize, true);
            
            // allocate buffer.
            bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t));
            // zero out buffer.
            memset((void *)bufferPtr, 0x0, bufferPtrSize);
            
            // initialize some necessary book keeping.
            ptr = bufferPtr;
            remainingBytes = bufferPtrSize;
            
            // perform the encryption or decryption.
            ccStatus = CCCryptorUpdate(cryptor,
                                       (const void *) [plainText bytes],
                                       plainTextBufferSize,
                                       ptr,
                                       remainingBytes,
                                       &movedBytes
                                       );
            
            if (ccStatus == kCCSuccess)
            {
                // handle bytes
                ptr += movedBytes;
                remainingBytes -= movedBytes;
                totalBytesWritten += movedBytes;
                
                // finalize everything to the output buffer.
                ccStatus = CCCryptorFinal(cryptor,
                                          ptr,
                                          remainingBytes,
                                          &movedBytes
                                          );
                
                totalBytesWritten += movedBytes;
                
                if (cryptor) {
                    (void) CCCryptorRelease(cryptor);
                    cryptor = NULL;
                }
                
                if (ccStatus == kCCSuccess)
                {
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
            NSString *bit = [digestBinary substringWithRange:NSMakeRange(j, 1)];
            if ([bit isEqualToString:@"1"]) {
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
    NSData *hash = nil;
    
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
            [input appendData:[DataFormatter hexStringToData:[DataFormatter hexFromInt:nonce prefix:YES]]];
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
