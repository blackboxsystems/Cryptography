#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import "DataFormatter.h"

#define kMSEC_IN_SEC 1000.0
#define APP_PROTOCOL_VERSION 1

#define PROTOCOL_VAULT_STRING @"vault"
#define PROTOCOL_VERSION_STRING @"version"
#define PROTOCOL_KDF_MODE_STRING @"kdfmode"
#define PROTOCOL_ENCRYPTION_MODE_STRING @"encmode"
#define PROTOCOL_SALT_STRING @"salt"
#define PROTOCOL_ROUNDS_STRING @"rounds"
#define PROTOCOL_IV_STRING @"iv"
#define PROTOCOL_HMAC_STRING @"hmac"
#define PROTOCOL_BLOB_STRING @"blob"

NS_ASSUME_NONNULL_BEGIN

@interface Protocol : NSObject

// encryption algorithm type
typedef NS_ENUM(NSInteger, BBEncryptionMode) {
    BBEncryptAES = kCCAlgorithmAES,
    BBEncryptOTP = 7
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
};


#pragma mark - JSON serializer
+ (NSString * _Nullable)jsonStringWithPrettyPrint:(id)object pretty:(BOOL)prettyPrint;

+ (NSData *)createProtocolWithBlob:(NSData *)data
                           kdfMode:(BBKDFMode)mode
                           encMode:(BBEncryptionMode)encMode
                              salt:(NSData *)salt
                            rounds:(NSInteger)rounds;


#pragma mark - PROTOCOL DATA FOR ONE-TIME-PROOF PAD
+ (NSData * _Nullable)createOTPProtocolData:(NSInteger)keyLength
                                     rounds:(NSInteger)rounds
                                       mode:(BBEncryptionMode)algo
                                 difficulty:(NSInteger)diff
                                       salt:(NSData *)salt;


#pragma mark - PARSING PROTOCOL FOR BACKUP DATA
+ (NSData * _Nullable)createBackupProtocolDataWithMode:(BBEncryptionMode)algo
                                                  salt:(NSData *)salt
                                                    iv:(NSData *)iv
                                                rounds:(NSInteger)rounds
                                                digest:(NSData *)digest;

#pragma mark - PARSING PROTOCOL DATA FOR AUTH KEY
+ (NSDictionary * _Nullable)parseBlob:(NSData *)data;

#pragma mark - GENERAL UNDERLYING PROTOCOL PARSING FUNCTION
+ (NSDictionary * _Nullable)protocolParser:(NSData *)data;

//+ (NSInteger)rangeForOpCode:(NSData *)opcode;

@end

NS_ASSUME_NONNULL_END
