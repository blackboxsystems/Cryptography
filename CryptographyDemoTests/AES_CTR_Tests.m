#import <XCTest/XCTest.h>
#import "Crypto.h"

//// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

#define KEY_CTR128  @"2B7E1516 28AED2A6 ABF71588 09CF4F3C"
#define KEY_CTR192  @"8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B"
#define KEY_CTR256  @"603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4"

#define ivec        @"F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF"

#define plainText1  @"6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710"

#define plainText2  @"7BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710"


#define kKDFRoundsTEST 1024

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

- (void)testPerformance_AES_CTR_Modes{
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
        [self test_AES_CTR_128];
        [self test_AES_CTR_192];
        [self test_AES_CTR_256];
    }];
}

/*
 test vectors:
 https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CTR.pdf
 */

- (void)test_AES_CTR_128{
    
    NSData *msg = [DataFormatter hexStringToData:plainText1];
    NSData *iv = [DataFormatter hexStringToData:ivec];
    NSData *key = [DataFormatter hexStringToData:KEY_CTR128];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CTR:msg key:key iv:iv];
    
    NSString *expectedEncryptedString = @"874D6191 B620E326 1BEF6864 990DB6CE 9806F66B 7970FDFF 8617187B B9FFFDFF 5AE4DF3E DBD5D35E 5B4F0902 0DB03EAB 1E031DDA 2FBE03D1 792170A0 F3009CEE";
    XCTAssertEqualObjects(encryptedData, [DataFormatter hexStringToData:expectedEncryptedString]);
    
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
- (void)test_AES_CTR_192{
    
    NSData *msg = [DataFormatter hexStringToData:plainText1];
    NSData *iv = [DataFormatter hexStringToData:ivec];
    NSData *key = [DataFormatter hexStringToData:KEY_CTR192];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CTR:msg key:key iv:iv];
    
    NSString *expectedEncryptedString = @"1ABC9324 17521CA2 4F2B0459 FE7E6E0B 090339EC 0AA6FAEF D5CCC2C6 F4CE8E94 1E36B26B D1EBC670 D1BD1D66 5620ABF7 4F78A7F6 D2980958 5A97DAEC 58C6B050";
    XCTAssertEqualObjects(encryptedData, [DataFormatter hexStringToData:expectedEncryptedString]);
    
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
- (void)test_AES_CTR_256{
    
    NSData *msg = [DataFormatter hexStringToData:plainText1];
    NSData *iv = [DataFormatter hexStringToData:ivec];
    NSData *key = [DataFormatter hexStringToData:KEY_CTR256];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CTR:msg key:key iv:iv];
    
    NSString *expectedEncryptedString = @"601EC313 775789A5 B7A7F504 BBF3D228 F443E3CA 4D62B59A CA84E990 CACAF5C5 2B0930DA A23DE94C E87017BA 2D84988D DFC9C58D B67AADA6 13C2DD08 457941A6";
    XCTAssertEqualObjects(encryptedData, [DataFormatter hexStringToData:expectedEncryptedString]);
    
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


// encrypting a block of data (all zeros) the same size as our plaintext bytes will
// output a key stream to XOR with the plaintext data to give the same encrypted result.
- (void)test_AES_CTR_EncryptionStreamXOR{
    
    NSData *msg = [DataFormatter hexStringToData:plainText1];
    
    NSData *blankMessage = [DataFormatter hexStringToData:@"00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"];
    
    NSData *key = [DataFormatter hexStringToData:@"603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4"];
    NSData *iv = [DataFormatter hexStringToData:@"F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF"];
    
    NSData *encryptedData = [Crypto encryptAES_CTR:blankMessage
                                               key:key
                                                iv:iv];
    NSData *xorEnc = [Crypto xorData:msg withData:encryptedData];
    
    XCTAssertEqualObjects(xorEnc, [DataFormatter hexStringToData:@"601ec313 775789a5 b7a7f504 bbf3d228 f443e3ca 4d62b59a ca84e990 cacaf5c5 2b0930da a23de94c e87017ba 2d84988d dfc9c58d b67aada6 13c2dd08 457941a6"]);
}
- (void)test_AES_CTR_EncryptionStreamXOR2{
    
    NSData *msg = [@"hello" dataUsingEncoding:NSUTF8StringEncoding];
    NSString *pad = @"00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000";
    
    NSData *blankMessage = [DataFormatter hexStringToData:pad];
    if (blankMessage.length > msg.length) {
        blankMessage = [blankMessage subdataWithRange:NSMakeRange(0, msg.length)];
    }
    
    NSData *key = [DataFormatter hexStringToData:@"00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001"];
    NSData *iv = [DataFormatter hexStringToData:@"00000000 00000000 00000000 00000000"];
    
    // encrypt empty data to create cipher pad stream of bytes
    NSData *keyStream = [Crypto encryptAES_CTR:blankMessage key:key iv:iv];
    
    // encrypt msg with key and iv
    NSData *encryptedMessageData = [Crypto encryptAES_CTR:msg key:key iv:iv];
    
    // obtain same encrypted result via xor'ing msg with key stream
    NSData *xorEncryptedData = [Crypto xorData:msg withData:keyStream];
//    NSLog(@"XOR EncryptedData[%li]: %@", xorEncryptedData.length, xorEncryptedData);
    XCTAssertEqualObjects(xorEncryptedData, encryptedMessageData);
    
    NSData *decryptedMsg = [Crypto xorData:keyStream withData:encryptedMessageData];
    
    XCTAssertEqualObjects(decryptedMsg, msg);
    
}

// localized encrypted data corruption using aes-ctr
- (void)test_AES_CTR_DataCorruption{
    
    NSString *secret = @"describe omit kite parent ask type noodle casino allow bench flavor amazing";
    NSData *msg = [secret dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key = [DataFormatter hexStringToData:@"01d4a0c5 aac82337 beda6d3b 3958d78b 944c68d9 a0700b74 8c2419d2 3fe7f4f7 efc17222 e94603ee e6964db5 f44d4c41 b4bf182a 7a7ef43e 9d4efa04 a7669026"];
    
    NSData *Kx = [key subdataWithRange:NSMakeRange(0, kAES256_KEY_LENGTH_BYTES)];
    NSData *iv = [DataFormatter hexStringToData:@"04a82b55518f6425030cbd17804643bd"];
    
    // encrypt
    NSMutableData *encryptedData = [[NSMutableData alloc] initWithData:[Crypto encryptAES_CTR:msg key:Kx iv:iv]];
    
    // corrupted the encrypted data
    NSInteger ncorrupt = 2;
    NSRange corruptRange = NSMakeRange(encryptedData.length-ncorrupt, ncorrupt);
    NSData *corruptData = [DataFormatter hexStringToData:@"428c"];
    
    // apply corrupt a portion of encrypted bytes
    [encryptedData replaceBytesInRange:corruptRange withBytes:corruptData.bytes];
    
    // decrypt corrupted data
    CCOptions pad = ccNoPadding;
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
