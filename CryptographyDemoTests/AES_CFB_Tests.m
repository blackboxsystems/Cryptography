#import <XCTest/XCTest.h>
#import "Crypto.h"


@interface AES_CFB_Tests : XCTestCase

@end

@implementation AES_CFB_Tests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)test_AES_CFB_Mode{
    
    NSData *plaintText = [DataFormatter hexStringToData:@"6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710"];    
    NSData *iv = [DataFormatter hexStringToData:@"00010203 04050607 08090A0B 0C0D0E0F"];
    NSData *key = [DataFormatter hexStringToData:@"603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4"];
//    NSInteger segmentLength = 128;
    
    // encrypt
    CCOptions pad = 0;
    NSData *encryptedData = [Crypto doCipher:plaintText
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeCFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"DC7E84BF DA79164B 7ECD8486 985D3860 39FFED14 3B28B1C8 32113C63 31E5407B DF101324 15E54B92 A13ED0A8 267AE2F9 75A38574 1AB9CEF8 2031623D 55B1E471"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeCFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, plaintText);
}



@end
