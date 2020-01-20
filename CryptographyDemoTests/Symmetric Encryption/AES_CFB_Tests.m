#import <XCTest/XCTest.h>
#import "Crypto.h"
#import "TestVectorConstants.h"
/*
    test vectors:
    - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CFB.pdf
    - https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
*/
@interface AES_CFB_Tests : XCTestCase

@end

@implementation AES_CFB_Tests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

//- (void)testPerformance_AES_CFB_Modes
//{
//    // This is an example of a performance test case.
//    [self measureBlock:^{
//        // Put the code you want to measure the time of here.
//        [self test_AES_CFB_128];
//        [self test_AES_CFB_192];
//        [self test_AES_CFB_256];
//    }];
//}

- (void)test_AES_CFB_128
{
    NSData *msg = [DataFormatter hexStringToData:AES_CFB_PLAINTEXT];
    
    NSData *iv = [DataFormatter hexStringToData:AES_CFB_IV];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_ECB128];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CFB:msg key:key iv:(NSData *)iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"3B3FD92E B72DAD20 333449F8 E83CFB4A C8A64537 A0B3A93F CDE3CDAD 9F1CE58B 26751F67 A3CBB140 B1808CF1 87A4F4DF C04B0535 7C5D1C0E EAC4C66F 9FF7F2E6"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto decryptAES_CFB:encryptedData key:key iv:(NSData *)iv];
    XCTAssertEqualObjects(decryptedData, msg);
}
- (void)test_AES_CFB_192
{
    NSData *msg = [DataFormatter hexStringToData:AES_CFB_PLAINTEXT];
    
    NSData *iv = [DataFormatter hexStringToData:AES_CFB_IV];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_ECB192];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CFB:msg key:key iv:(NSData *)iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"CDC80D6F DDF18CAB 34C25909 C99A4174 67CE7F7F 81173621 961A2B70 171D3D7A 2E1E8A1D D59B88B1 C8E60FED 1EFAC4C9 C05F9F9C A9834FA0 42AE8FBA 584B09FF"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto decryptAES_CFB:encryptedData key:key iv:(NSData *)iv];
    XCTAssertEqualObjects(decryptedData, msg);
}
- (void)test_AES_CFB_256
{
    NSData *msg = [DataFormatter hexStringToData:AES_CFB_PLAINTEXT];
    
    NSData *iv = [DataFormatter hexStringToData:AES_CFB_IV];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_ECB256];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CFB:msg key:key iv:(NSData *)iv];
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"DC7E84BF DA79164B 7ECD8486 985D3860 39FFED14 3B28B1C8 32113C63 31E5407B DF101324 15E54B92 A13ED0A8 267AE2F9 75A38574 1AB9CEF8 2031623D 55B1E471"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto decryptAES_CFB:encryptedData key:key iv:(NSData *)iv];
    XCTAssertEqualObjects(decryptedData, msg);
}



@end

