#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import "DataFormatter.h"
#import "Protocol.h"


// key derivation rounds
#define kPBKDFRoundsDefault 4096
#define kMaxNonce 4294967295

// key length bytes
#define kAES256_IV_LENGTH_BYTES 16      // 128 bit block size
#define kAES256_KEY_LENGTH_BYTES 32     // output size in bytes for 256 bit symmetric key

#define kHMAC_SHA256_SALT_LENGTH 32     // output size in bytes HMAC_SHA256
#define kHMAC_SHA512_SALT_LENGTH 64     // output size in bytes HMAC_SHA512

#define kKDFRoundsDigest256 924137
#define kKDFRoundsDigest512 656621

@interface Crypto : NSObject


// cryptographically secure random bytes
+ (NSData *)generateRandomCrytoBytes:(size_t )Nbytes;

// SHA hash
+ (NSData *)sha256:(NSData *)data;
+ (NSData *)sha512:(NSData *)data;
+ (NSData *)sha:(NSData *)data
          nbits:(NSInteger)nbits;

// Hashed Message Authentication Code
+ (NSData *)hmac:(NSData *)data
             key:(NSData *)key
           nbits:(NSInteger)digestSize;

// key derivation
+ (NSData *)deriveKey:(NSString *)password
                 salt:(NSData *)salt
                 mode:(BBKDFMode)m
               rounds:(NSInteger)rounds;

#pragma mark - KEY DERIVATION ROUNDS
+ (NSUInteger)KDFRoundsForDerivationTime:(double)ms
                          passwordLength:(size_t)passwordLen
                              saltLength:(size_t)saltLen
                             ccAlgorithm:(CCPseudoRandomAlgorithm)ccAlgorithm
                        derivedKeyLength:(size_t)keyLength;

+ (NSData *)getIV:(NSInteger)nbytes;

// wrapper for encryption/decryption
+ (NSData *)encrypt:(NSData *)data
                key:(NSData *)key
                 iv:(NSData *)iv;
+ (NSData *)decrypt:(NSData *)data
                key:(NSData *)key
                 iv:(NSData *)iv;

+ (NSData *)encryptAES_CTR:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv;
+ (NSData *)decryptAES_CTR:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv;

// encrypt-then-mac
+ (NSData *)encryptThenMAC:(NSData *)data
                    intKey:(NSData *)Kak
                    encKey:(NSData *)Kek;

// check mac then decrypt
+ (NSData *)decryptWithMAC:(NSData *)data
                    intKey:(NSData *)Ky
                    encKey:(NSData *)Kx;

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
