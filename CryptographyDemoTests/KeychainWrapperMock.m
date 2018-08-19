#import "KeychainWrapperMock.h"
#import "Crypto.h"

@implementation KeychainWrapperMock

#pragma mark - MOCK FOR TESTING KEYCHAIN FUNCTIONALITY

+ (OSStatus)createRandomECCKey_TEST{
    
    NSMutableDictionary *keyPairAttr = [self initECCKeyPairAttributes_TEST];
    
    SecKeyRef publicKey = NULL;
    SecKeyRef privateKey = NULL;
    
    OSStatus status = noErr;
    CFErrorRef error;
    
    privateKey = SecKeyCreateRandomKey((CFDictionaryRef)keyPairAttr, &error);
    publicKey = SecKeyCopyPublicKey(privateKey);
    
    if(privateKey != NULL || publicKey != NULL) {
        status = errSecSuccess;
    } else {
        status = errSecParam;
    }
    
    if (status == errSecSuccess)
    {
        status = [self AddECCKey_TEST:privateKey isPrivate:YES];
        
        if (status == errSecSuccess) {
            status = [self AddECCKey_TEST:publicKey isPrivate:NO];
        }
    }
    
    if (privateKey != NULL) {
        CFRelease(privateKey);
    }
    
    if (publicKey != NULL) {
        CFRelease(publicKey);
    }
    
    return status;
}
+ (NSMutableDictionary *)initECCPublicKeyAttributes_TEST{
    
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    
    NSData *publicTag = [NSData dataWithBytes:kKEYCHAIN_TAG_ECC_TEST
                                       length:strlen((const char *)kKEYCHAIN_TAG_ECC_TEST)];
    [publicKeyAttr setObject:publicTag
                      forKey:(id)kSecAttrApplicationTag];
    [publicKeyAttr setObject:(id)kSecClassKey
                      forKey:(id)kSecClass];
    [publicKeyAttr setObject:(id)kSecAttrKeyTypeEC
                      forKey:(id)kSecAttrKeyType];
    [publicKeyAttr setObject:[NSNumber numberWithInt:kECC_KEY_LENGTH_256]
                      forKey:(id)kSecAttrKeySizeInBits];
    [publicKeyAttr setObject:(id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
                      forKey:(id)kSecAttrAccessible];
    
    return publicKeyAttr;
}
+ (NSMutableDictionary *)initECCPrivateKeyAttributes_TEST{
    
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    
    NSData *privateTag = [NSData dataWithBytes:kKEYCHAIN_TAG_ECC_TEST
                                        length:strlen((const char *)kKEYCHAIN_TAG_ECC_TEST)];
    [privateKeyAttr setObject:privateTag
                       forKey:(id)kSecAttrApplicationTag];
    [privateKeyAttr setObject:(id)kSecClassKey
                       forKey:(id)kSecClass];
    [privateKeyAttr setObject:(id)kSecAttrKeyTypeEC
                       forKey:(id)kSecAttrKeyType];
    [privateKeyAttr setObject:[NSNumber numberWithInt:kECC_KEY_LENGTH_256]
                       forKey:(id)kSecAttrKeySizeInBits];
    [privateKeyAttr setObject:(id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
                       forKey:(id)kSecAttrAccessible];
    
    return privateKeyAttr;
}
+ (NSMutableDictionary *)initECCKeyPairAttributes_TEST{
    
    NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *privateKeyAttr = [self initECCPrivateKeyAttributes_TEST];
    NSMutableDictionary *publicKeyAttr = [self initECCPublicKeyAttributes_TEST];
    
    [keyPairAttr setObject:(id)kSecClassKey
                    forKey:(id)kSecClass];
    [keyPairAttr setObject:(id)kSecAttrKeyTypeEC
                    forKey:(id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithInt:kECC_KEY_LENGTH_256]
                    forKey:(id)kSecAttrKeySizeInBits];
    [keyPairAttr setObject:privateKeyAttr
                    forKey:(id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr
                    forKey:(id)kSecPublicKeyAttrs];
    
    return keyPairAttr;
}
+ (OSStatus)AddECCKey_TEST:(SecKeyRef)key isPrivate:(BOOL)isPrivate{
    
    NSMutableDictionary *keyAttr;
    NSData *keyTag = [NSData dataWithBytes:kKEYCHAIN_TAG_ECC_TEST
                                    length:strlen((const char *)kKEYCHAIN_TAG_ECC_TEST)];
    
    [keyAttr setObject:keyTag
                forKey:(__bridge id)kSecAttrApplicationTag];
    [keyAttr setObject:(__bridge id)kSecClassKey
                forKey:(__bridge id)kSecClass];
    [keyAttr setObject:(__bridge id)kSecAttrKeyTypeEC
                forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:(id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
                forKey:(id)kSecAttrAccessible];
    
    if (isPrivate) {
        keyAttr = [self initECCPrivateKeyAttributes_TEST];
    } else {
        keyAttr = [self initECCPublicKeyAttributes_TEST];
    }
    
    [keyAttr setObject:(__bridge id)key
                forKey:(__bridge id)kSecValueRef];
    
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef) keyAttr, nil);
    
    if (status == errSecDuplicateItem)
    {
        status = SecItemDelete((__bridge CFDictionaryRef)keyAttr);
        if (status == errSecSuccess) {
            return SecItemAdd((__bridge CFDictionaryRef)keyAttr, nil);
        }
    }
    
    return status;
}
+ (NSData *)getPublicECCKeyData_TEST{
    
    OSStatus status = noErr;
    CFTypeRef result = NULL;
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    
    NSData *keyTag = [NSData dataWithBytes:kKEYCHAIN_TAG_ECC_TEST
                                    length:strlen((const char *)kKEYCHAIN_TAG_ECC_TEST)];
    [publicKeyAttr setObject:keyTag
                      forKey:(id)kSecAttrApplicationTag];
    [publicKeyAttr setObject:(id)kSecClassKey
                      forKey:(id)kSecClass];
    [publicKeyAttr setObject:(id)kSecAttrKeyTypeEC
                      forKey:(id)kSecAttrKeyType];
    [publicKeyAttr setObject:(id)kCFBooleanTrue
                      forKey:(id)kSecReturnData];
    [publicKeyAttr setObject:(id)kSecAttrKeyClassPublic
                      forKey:(id)kSecAttrKeyClass];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKeyAttr, &result);
    
    if (status == errSecSuccess) {
        return CFBridgingRelease(result);
    }
    
    return nil;
}
+ (SecKeyRef)getPublicECCKeyRef_TEST{
    
    OSStatus status = noErr;
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    
    NSData *keyTag = [NSData dataWithBytes:kKEYCHAIN_TAG_ECC_TEST
                                    length:strlen((const char *)kKEYCHAIN_TAG_ECC_TEST)];
    
    [publicKeyAttr setObject:keyTag
                      forKey:(id)kSecAttrApplicationTag];
    [publicKeyAttr setObject:(id)kSecClassKey
                      forKey:(id)kSecClass];
    [publicKeyAttr setObject:(id)kSecAttrKeyTypeEC
                      forKey:(id)kSecAttrKeyType];
    [publicKeyAttr setObject:(id)kCFBooleanTrue
                      forKey:(id)kSecReturnRef];
    [publicKeyAttr setObject:(id)kSecAttrKeyClassPublic
                      forKey:(id)kSecAttrKeyClass];
    
    CFTypeRef result;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKeyAttr, &result);
    
    if (status == errSecSuccess) {
        return (SecKeyRef)result;
    }
    
    return nil;
}
+ (SecKeyRef)getPrivateECCKeyRef_TEST{
    
    OSStatus status = noErr;
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    
    NSData *keyTag = [NSData dataWithBytes:kKEYCHAIN_TAG_ECC_TEST
                                    length:strlen((const char *)kKEYCHAIN_TAG_ECC_TEST)];
    [privateKeyAttr setObject:keyTag
                       forKey:(id)kSecAttrApplicationTag];
    [privateKeyAttr setObject:(id)kSecClassKey
                       forKey:(id)kSecClass];
    [privateKeyAttr setObject:(id)kSecAttrKeyTypeEC
                       forKey:(id)kSecAttrKeyType];
    [privateKeyAttr setObject:(id)kCFBooleanTrue
                       forKey:(id)kSecReturnRef];
    [privateKeyAttr setObject:(id)kSecAttrKeyClassPrivate
                       forKey:(id)kSecAttrKeyClass];
    
    CFTypeRef result;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)privateKeyAttr, &result);

    if (status == errSecSuccess) {
        return (SecKeyRef)result;
    }
    
    return nil;
}
+ (OSStatus)deleteECCKeyPair_TEST{
    
    // Create Public Key Query For Deletion
    NSMutableDictionary *keyPairAttrs = [[NSMutableDictionary alloc] init];
    NSData *keyTag = [NSData dataWithBytes:kKEYCHAIN_TAG_ECC_TEST
                                    length:strlen((const char *)kKEYCHAIN_TAG_ECC_TEST)];
    [keyPairAttrs setObject:keyTag
                     forKey:(id)kSecAttrApplicationTag];
    [keyPairAttrs setObject:(id)kSecClassKey
                     forKey:(id)kSecClass];
    
    OSStatus status = SecItemDelete((CFDictionaryRef)keyPairAttrs);
    return status;
}


+ (NSData *)createECCDigitalSignature_TEST:(NSData *)digest{
    
    SecKeyRef privateKey = [self getPrivateECCKeyRef_TEST];
    CFErrorRef error = NULL;
    
    // sign the message digest
    CFTypeRef sigData = SecKeyCreateSignature(privateKey,
                                              kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
                                              (CFDataRef)digest,
                                              &error);
    
    NSData *signature = CFBridgingRelease(sigData);
    
    if (privateKey) {
        CFRelease(privateKey);
    }
    
    return signature;
}
+ (BOOL)verifyECCDigitalSignature_TEST:(NSData *)digest signature:(NSData *)signature{
    
    SecKeyRef publicKey = [self getPublicECCKeyRef_TEST];
    
    if (digest == nil) {
        return NO;
    }
    
    CFTypeRef sigData = (__bridge CFTypeRef)(signature);
    CFErrorRef error = NULL;
    BOOL validSig = NO;
    
    // verify the signature
    validSig = SecKeyVerifySignature(publicKey,
                                     kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
                                     (CFDataRef)digest,
                                     sigData,
                                     &error
                                     );
    
    if (publicKey) {
        CFRelease(publicKey);
    }
    return validSig;
}


@end
