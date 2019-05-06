#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import "DataFormatter.h"

#define kMSEC_IN_SEC 1000.0
#define APP_PROTOCOL_VERSION 1

#define PROTOCOL_VERSION_KEY @"version"
#define PROTOCOL_KDF_MODE_KEY @"kdfmode"
#define PROTOCOL_ENCRYPTION_MODE_KEY @"encmode"

#define PROTOCOL_SALT_KEY @"salt"
#define PROTOCOL_ROUNDS_KEY @"rounds"
#define PROTOCOL_DIFFICULTY_KEY @"difficulty"
#define PROTOCOL_IV_KEY @"iv"
#define PROTOCOL_HMAC_KEY @"hmac"
#define PROTOCOL_BLOB_KEY @"blob"

NS_ASSUME_NONNULL_BEGIN

@interface Protocol : NSObject

// encryption algorithm type
typedef NS_ENUM(NSInteger, BBEncryptionMode) {
    BBEncryptAES = kCCAlgorithmAES,
    BBEncryptOTP = 7,
    BBEncryptOTP_POW,
    BBEncryptOTP_TIME
};

// encryption algorithm type
typedef NS_ENUM(NSInteger, AESBlockSize) {
    AESBlockSize128 = 128,
    AESBlockSize196 = 196,
    AESBlockSize256 = 256
};

// key derivation mode
typedef NS_ENUM(NSInteger, BBKDFMode) {
    unknown = 0,
    masterKey,
    enclaveKey,
    pincodeKey,
    aesKey,
    otp256,
    otp512
};


#pragma mark - JSON serializer
+ (NSString * _Nullable)jsonStringWithPrettyPrint:(id)object pretty:(BOOL)prettyPrint;

+ (NSData *)createProtocolWithBlob:(NSData *)data
                           kdfMode:(BBKDFMode)mode
                           encMode:(BBEncryptionMode)encMode
                              salt:(NSData *)salt
                            rounds:(NSInteger)rounds;


+ (NSData *)createOTPProtocolData:(NSData *)data
                             salt:(NSData *)salt
                           rounds:(NSInteger)rounds
                          kdfmode:(BBKDFMode)kdfMode
                          encmode:(BBEncryptionMode)encmode
                       difficulty:(NSInteger)difficulty;

#pragma mark - PARSE WRAPPER
+ (NSDictionary * _Nullable)parseBlob:(NSData *)data;

#pragma mark - PROTOCOL PARSER
+ (NSDictionary * _Nullable)protocolParser:(NSData *)data;

@end

NS_ASSUME_NONNULL_END
