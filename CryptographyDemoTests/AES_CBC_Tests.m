#import <XCTest/XCTest.h>
#import "Crypto.h"

// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

#define KEY_CBC128  @"2B7E1516 28AED2A6 ABF71588 09CF4F3C"
#define KEY_CBC192  @"8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B"
#define KEY_CBC256  @"603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4"

#define ivec        @"00010203 04050607 08090A0B 0C0D0E0F"

#define plainText  @"6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710"

@interface AES_CBC_Tests : XCTestCase

@end

@implementation AES_CBC_Tests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

//- (void)testPerformance_AES_CBC_Modes{
//    // This is an example of a performance test case.
//    [self measureBlock:^{
//        // Put the code you want to measure the time of here.
//        [self test_AES_CBC_128];
//        [self test_AES_CBC_192];
//        [self test_AES_CBC_256];
//    }];
//}
- (void)test_AES_CBC_128{
    
    
    NSData *msg = [DataFormatter hexStringToData:plainText];
    NSData *iv = [DataFormatter hexStringToData:ivec];
    NSData *key = [DataFormatter hexStringToData:KEY_CBC128];
    
    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeCBC
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"7649ABAC 8119B246 CEE98E9B 12E9197D 5086CB9B 507219EE 95DB113A 917678B2 73BED6B8 E3C1743B 7116E69E 22229516 3FF1CAA1 681FAC09 120ECA30 7586E1A7"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeCBC
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, msg);
}

- (void)test_AES_CBC_192{
    
    
    NSData *msg = [DataFormatter hexStringToData:plainText];
    NSData *iv = [DataFormatter hexStringToData:ivec];
    NSData *key = [DataFormatter hexStringToData:KEY_CBC192];
    
    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeCBC
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"4F021DB2 43BC633D 7178183A 9FA071E8 B4D9ADA9 AD7DEDF4 E5E73876 3F69145A 571B2420 12FB7AE0 7FA9BAAC 3DF102E0 08B0E279 88598881 D920A9E6 4F5615CD"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeCBC
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, msg);
}
- (void)test_AES_CBC_256{
    
    
    NSData *msg = [DataFormatter hexStringToData:plainText];
    NSData *iv = [DataFormatter hexStringToData:ivec];
    NSData *key = [DataFormatter hexStringToData:KEY_CBC256];
    
    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeCBC
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"F58C4C04 D6E5F1BA 779EABFB 5F7BFBD6 9CFC4E96 7EDB808D 679F777B C6702C7D 39F23369 A9D9BACF A530E263 04231461 B2EB05E2 C39BE9FC DA6C1907 8C6A9D1B"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeCBC
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, msg);
}

@end
