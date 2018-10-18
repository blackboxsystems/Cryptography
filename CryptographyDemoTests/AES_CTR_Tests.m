#import <XCTest/XCTest.h>
#import "Crypto.h"

@interface AES_CTR_Tests : XCTestCase

@end

@implementation AES_CTR_Tests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}


- (void)test_AES_CTR_encrypt_decrypt{
    
    // derive an encryption key from a password and encrypt
    NSString *password = @"test";
    NSData *msg = [@"Hi There" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *salt = [DataFormatter hexStringToData:@"601b326a6e2f5ab48907ff13e474939b55a7e9d448696c0febd4621208715222"];
    NSData *iv = [DataFormatter hexStringToData:@"e3a982494277626b8eacc3d6a750367c"];
    
    // derive
    NSData *key = [Crypto deriveKey:password
                               salt:salt
                               mode:BBDeriveAES
                             rounds:kKDFRoundsDigest256];
    
    // encrypt
    NSData *encryptedData = [Crypto encrypt:msg key:key iv:iv];
    NSString *encryptedString = [DataFormatter hexDataToString:encryptedData];
    XCTAssertEqualObjects(encryptedString, @"9de48a1fb6804038");
    
    // decrypt
    CCOptions pad = 0;
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeCTR
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, msg);
}


// encrypting a block of data (all zeros) the same size as our plaintext bytes
// will output a key stream to xor with the plaintext data to give the encrypted
// result.
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CTR.pdf

- (void)test_AES_CTR_EncryptionStreamXOR{
    NSData *plaintText = [DataFormatter hexStringToData:@"6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710"];
    NSData *blankMessage = [DataFormatter hexStringToData:@"00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"];
    
    NSData *key = [DataFormatter hexStringToData:@"603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4"];
    NSData *iv = [DataFormatter hexStringToData:@"F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF"];
    
    NSData *encryptedData = [Crypto encrypt:blankMessage key:key iv:iv];
    NSData *xorEnc = [Crypto xorData:plaintText withData:encryptedData];
    
//    NSLog(@"\n\nencryptedData: %@\nxor: %@", encryptedData, xorEnc);
    XCTAssertEqualObjects(xorEnc, [DataFormatter hexStringToData:@"601ec313 775789a5 b7a7f504 bbf3d228 f443e3ca 4d62b59a ca84e990 cacaf5c5 2b0930da a23de94c e87017ba 2d84988d dfc9c58d b67aada6 13c2dd08 457941a6"]);
}


// localized encrypted data corruption...
// ...could also be used to encrypt a range of ciphertext for
// access control on certain fields...
- (void)test_AES_CTR_DataCorruption {
    
    /*
     Deriving, Encrypting and Packing
     */
    NSString *secret = @"describe omit kite parent ask type noodle casino allow bench flavor amazing";
    NSData *msg = [secret dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key = [DataFormatter hexStringToData:@"01d4a0c5 aac82337 beda6d3b 3958d78b 944c68d9 a0700b74 8c2419d2 3fe7f4f7 efc17222 e94603ee e6964db5 f44d4c41 b4bf182a 7a7ef43e 9d4efa04 a7669026"];
    
    NSData *Kx = [key subdataWithRange:NSMakeRange(0, kAES256_KEY_LENGTH)];
    NSData *iv = [DataFormatter hexStringToData:@"04a82b55518f6425030cbd17804643bd"];
    
    // encrypt
    NSMutableData *encryptedData = [[NSMutableData alloc] initWithData:[Crypto encrypt:msg key:Kx iv:iv]];
    
    // corrupted the encrypted data
    NSInteger ncorrupt = 2;
    NSRange corruptRange = NSMakeRange(encryptedData.length-ncorrupt, ncorrupt);
    NSData *corruptData = [DataFormatter hexStringToData:@"428c"];
    
    // apply corrupt a portion of encrypted bytes
    [encryptedData replaceBytesInRange:corruptRange withBytes:corruptData.bytes];
    
    // decrypt corrupted data
    CCOptions pad = 0;
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:Kx
                                     context:kCCDecrypt
                                        mode:kCCModeCTR
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSRange validRange = NSMakeRange(0, decryptedData.length-ncorrupt);
    XCTAssertEqualObjects([msg subdataWithRange:validRange], [decryptedData subdataWithRange:validRange]);
    XCTAssertNotEqualObjects(msg, decryptedData);
}



@end
