#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import "DataFormatter.h"
#import "Protocol.h"


// key derivation rounds
#define kPBKDFRoundsAES 4096
#define kMaxNonce 4294967295
#define kAES256_IV_LENGTH 16
#define kAES256_KEY_LENGTH 32
#define kSHAHMAC256_SALT_LENGTH 32
#define kSHAHMAC512_SALT_LENGTH 64

#define kKDFRoundsDigest256 924137
#define kKDFRoundsDigest512 656621

@interface Crypto : NSObject


// cryptographically secure random bytes
+ (NSData *)generateRandomCrytoBytes:(size_t )Nbytes;

// SHA hash
+ (NSData *)sha256:(NSData *)data;
+ (NSData *)sha:(NSData *)data
          nbits:(NSInteger)nbytes;

// Hashed Message Authentication Code
+ (NSData *)hmac:(NSData *)data
             key:(NSData *)key
           nbits:(NSInteger)digestSize;

// key derivation
+ (NSData *)deriveKey:(NSString *)password
                 salt:(NSData *)salt
                 mode:(BBKeyDerivationMode)m
               rounds:(NSInteger)rounds;

#pragma mark - KEY DERIVATION ROUNDS
+ (NSUInteger)KDFRoundsForDerivationTime:(double)ms
                          passwordLength:(size_t)passwordLen
                              saltLength:(size_t)saltLen
                             ccAlgorithm:(CCPseudoRandomAlgorithm)ccAlgorithm
                        derivedKeyLength:(size_t)keyLength;

+ (NSData *)getIV:(NSInteger)nbytes;

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

#pragma mark - SYMMETRIC ENCRYPTION
+ (NSData *)doCipher:(NSData *)plainText
                 key:(NSData *)key
             context:(CCOperation)encryptOrDecrypt
                mode:(CCMode)mode
           algorithm:(CCAlgorithm)algo
             padding:(CCOptions *)padding
                  iv:(NSData *)iv;

// xor operation
+ (NSData *)xorData:(NSData *)data1
           withData:(NSData *)data2;

// lamport signature generation
+ (NSData *)generateLamportSignature:(NSData *)digest;

// proof of work algorithm
+ (NSDictionary *)proofOfWork:(NSData *)challenge difficulty:(NSInteger)diff;

@end
