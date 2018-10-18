#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import "DataFormatter.h"

#define kMSEC_IN_SEC 1000.0
#define APP_PROTOCOL_VERSION 1

NS_ASSUME_NONNULL_BEGIN

@interface Protocol : NSObject

// encryption algorithm type
typedef NS_ENUM(NSInteger, BBEncryptionMode) {
    BBEncryptAES = kCCAlgorithmAES,
    BBEncryptOTP = 7
};

// key derivation mode
typedef NS_ENUM(NSInteger, BBKeyDerivationMode) {
    BBDeriveKEY = 0,
    BBDeriveAES = 1,
    BBDeriveOTHER
};

#pragma mark - JSON serializer
+ (NSString * _Nullable)jsonStringWithPrettyPrint:(id)object pretty:(BOOL)prettyPrint;

#pragma mark - PROTOCOL DATA FOR AUTH KEY
+ (NSData * _Nullable)createProtocolData:(NSInteger)keyLength
                                  rounds:(NSInteger)rounds
                                    mode:(BBEncryptionMode)algo
                                    salt:(NSData *)salt
                                    data:(NSData *)data;


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