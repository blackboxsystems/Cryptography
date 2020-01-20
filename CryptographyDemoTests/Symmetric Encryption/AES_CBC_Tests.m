#import <XCTest/XCTest.h>
#import "Crypto.h"
#import "TestVectorConstants.h"
/*
    test vectors:
    - https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
*/
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

- (void)test_AES_CBC_128
{
    NSData *msg = [DataFormatter hexStringToData:AES_CBC_PLAINTEXT];

    NSData *iv = [DataFormatter hexStringToData:AES_IV_CBC];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_CBC128];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CBC:msg key:key iv:(NSData *)iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"7649ABAC 8119B246 CEE98E9B 12E9197D 5086CB9B 507219EE 95DB113A 917678B2 73BED6B8 E3C1743B 7116E69E 22229516 3FF1CAA1 681FAC09 120ECA30 7586E1A7"];
    
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto decryptAES_CBC:encryptedData key:key iv:(NSData *)iv];
    XCTAssertEqualObjects(decryptedData, msg);
}

- (void)test_AES_CBC_192
{
    NSData *msg = [DataFormatter hexStringToData:AES_CBC_PLAINTEXT];

    NSData *iv = [DataFormatter hexStringToData:AES_IV_CBC];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_CBC192];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CBC:msg key:key iv:(NSData *)iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"4F021DB2 43BC633D 7178183A 9FA071E8 B4D9ADA9 AD7DEDF4 E5E73876 3F69145A 571B2420 12FB7AE0 7FA9BAAC 3DF102E0 08B0E279 88598881 D920A9E6 4F5615CD"];
    
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto decryptAES_CBC:encryptedData key:key iv:(NSData *)iv];
    XCTAssertEqualObjects(decryptedData, msg);
}

- (void)test_AES_CBC_256
{
    NSData *msg = [DataFormatter hexStringToData:AES_CBC_PLAINTEXT];

    NSData *iv = [DataFormatter hexStringToData:AES_IV_CBC];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_CBC256];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CBC:msg key:key iv:(NSData *)iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"F58C4C04 D6E5F1BA 779EABFB 5F7BFBD6 9CFC4E96 7EDB808D 679F777B C6702C7D 39F23369 A9D9BACF A530E263 04231461 B2EB05E2 C39BE9FC DA6C1907 8C6A9D1B"];
    
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto decryptAES_CBC:encryptedData key:key iv:(NSData *)iv];
    XCTAssertEqualObjects(decryptedData, msg);
}

- (void)test_AES_CBC_128_empty_message
{
    NSData *msg = [DataFormatter hexStringToData:BLANK_PLAINTEXT_32];

    NSData *iv = [DataFormatter hexStringToData:AES_IV_CBC_01];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_CBC128_0];
    NSData *key2 = [DataFormatter hexStringToData:AES_KEY_CBC128_1];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CBC:msg key:key iv:(NSData *)iv];
    NSData *encryptedData2 = [Crypto encryptAES_CBC:encryptedData key:key2 iv:(NSData *)iv];
//    NSLog(@"\n\nE1:\n%@\nE2:\n%@", encryptedData, encryptedData2);

    // decrypt
    NSData *decryptedData = [Crypto decryptAES_CBC:encryptedData2 key:key2 iv:(NSData *)iv];
    NSData *decryptedData2 = [Crypto decryptAES_CBC:decryptedData key:key iv:(NSData *)iv];
//    NSLog(@"\n\nD1:\n%@\nD2:\n%@", decryptedData, decryptedData2);
    
    XCTAssertEqualObjects(decryptedData2, msg);
}

@end
