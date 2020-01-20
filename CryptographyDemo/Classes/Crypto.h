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

#pragma mark - AES CTR
+ (NSData *)encryptAES_CTR:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv;

+ (NSData *)decryptAES_CTR:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv;

#pragma mark - AES CBC
+ (NSData *)encryptAES_CBC:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv;

+ (NSData *)decryptAES_CBC:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv;

#pragma mark - AES CFB
+ (NSData *)encryptAES_CFB:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv;

+ (NSData *)decryptAES_CFB:(NSData *)data
                       key:(NSData *)key
                        iv:(NSData *)iv;

#pragma mark - Encrypt-Then-Mac
+ (NSData *)encryptThenMAC:(NSData *)data
                    encKey:(NSData *)Kek
                    intKey:(NSData *)Kak;

#pragma mark - Check-Mac-Then-Decrypt
+ (NSData *)decryptWithMAC:(NSData *)data
                    encKey:(NSData *)Kx
                    intKey:(NSData *)Ky;

#pragma mark - Encrypt-Then-Merkle
+ (NSData *)encryptThenMerkle:(NSData *)data
                       encKey:(NSData *)Kek
                       intKey:(NSData *)Kak;

#pragma mark - Check-Merkle-Then-Decrypt
+ (NSData *)decryptWithMerkle:(NSData *)data
                       encKey:(NSData *)Kx
                       intKey:(NSData *)Ky;


#pragma mark - SYMMETRIC ENCRYPTION MODES
+ (NSData *)doCipher:(NSData *)plainText
                 key:(NSData *)key
             context:(CCOperation)encryptOrDecrypt
                mode:(CCMode)mode
           algorithm:(CCAlgorithm)algo
             padding:(CCOptions *)padding
                  iv:(NSData *)iv;

#pragma mark - XOR DATA SHORT
+ (NSData *)xorData:(NSData *)data1
           withData:(NSData *)data2;

#pragma mark - XOR DATA LONG
+ (NSData *)xorDataLong:(NSData *)data1
               withData:(NSData *)data2;

#pragma mark - LAMPORT SIGNATURE
+ (NSData *)generateLamportSignature:(NSData *)digest;

#pragma mark - PROOF OF WORK
+ (NSDictionary *)proofOfWork:(NSData *)challenge difficulty:(NSInteger)diff;


@end
