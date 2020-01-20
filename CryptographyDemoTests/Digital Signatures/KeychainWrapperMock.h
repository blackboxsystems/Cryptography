#import <Foundation/Foundation.h>

#define kKEYCHAIN_TAG_ECC_TEST "com.cryptographydemotests.test.ecc"
#define kECC_KEY_LENGTH_256 256

@interface KeychainWrapperMock : NSObject

#pragma mark - MOCK FOR KEYCHAIN WRAPPER CLASSES AND FUNCTIONS
+ (OSStatus)createRandomECCKey_TEST;
+ (NSMutableDictionary *)initECCKeyPairAttributes_TEST;
+ (NSMutableDictionary *)initECCPrivateKeyAttributes_TEST;
+ (NSMutableDictionary *)initECCPublicKeyAttributes_TEST;
+ (OSStatus)AddECCKey_TEST:(SecKeyRef)key isPrivate:(BOOL)isPrivate;

+ (NSData *)getPublicECCKeyData_TEST;
+ (SecKeyRef)getPublicECCKeyRef_TEST;
+ (SecKeyRef)getPrivateECCKeyRef_TEST;
+ (OSStatus)deleteECCKeyPair_TEST;

+ (NSData *)createECCDigitalSignature_TEST:(NSData *)digest;
+ (BOOL)verifyECCDigitalSignature_TEST:(NSData *)digest signature:(NSData *)signature;


@end
