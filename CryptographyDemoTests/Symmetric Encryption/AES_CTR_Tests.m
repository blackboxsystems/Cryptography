#import <XCTest/XCTest.h>
#import "Crypto.h"
#import "TestVectorConstants.h"
/*
    test vectors:
    - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CTR.pdf
    - https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
*/
@interface AES_CTR_Tests : XCTestCase

@end

@implementation AES_CTR_Tests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

//- (void)testPerformance_AES_CTR_Modes
//{
//    // This is an example of a performance test case.
//    [self measureBlock:^{
//        // Put the code you want to measure the time of here.
//        [self test_AES_CTR_128];
//        [self test_AES_CTR_192];
//        [self test_AES_CTR_256];
//    }];
//}

- (void)test_AES_CTR_128
{
    NSData *msg = [DataFormatter hexStringToData:AES_MODE_PLAINTEXT];
    
    NSData *iv = [DataFormatter hexStringToData:AES_IV_CTR];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_CTR128];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CTR:msg
                                               key:key
                                                iv:iv];
    
    // check encryption
    NSString *expectedEncryptedString = @"874D6191 B620E326 1BEF6864 990DB6CE 9806F66B 7970FDFF 8617187B B9FFFDFF 5AE4DF3E DBD5D35E 5B4F0902 0DB03EAB 1E031DDA 2FBE03D1 792170A0 F3009CEE";
    XCTAssertEqualObjects(encryptedData, [DataFormatter hexStringToData:expectedEncryptedString]);
    
    // check decryption
    NSData *decryptedData = [Crypto decryptAES_CTR:encryptedData key:key iv:iv];
    XCTAssertEqualObjects(decryptedData, msg);
}
- (void)test_AES_CTR_192
{
    NSData *msg = [DataFormatter hexStringToData:AES_MODE_PLAINTEXT];
    
    NSData *iv = [DataFormatter hexStringToData:AES_IV_CTR];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_CTR192];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CTR:msg
                                               key:key
                                                iv:iv];
    
    // check encryption
    NSString *expectedEncryptedString = @"1ABC9324 17521CA2 4F2B0459 FE7E6E0B 090339EC 0AA6FAEF D5CCC2C6 F4CE8E94 1E36B26B D1EBC670 D1BD1D66 5620ABF7 4F78A7F6 D2980958 5A97DAEC 58C6B050";
    XCTAssertEqualObjects(encryptedData, [DataFormatter hexStringToData:expectedEncryptedString]);
    
    // check decryption
    NSData *decryptedData = [Crypto decryptAES_CTR:encryptedData key:key iv:iv];
    XCTAssertEqualObjects(decryptedData, msg);
}
- (void)test_AES_CTR_256
{
    NSData *msg = [DataFormatter hexStringToData:AES_MODE_PLAINTEXT];
    
    NSData *iv = [DataFormatter hexStringToData:AES_IV_CTR];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_CTR256];
    
    // encrypt
    NSData *encryptedData = [Crypto encryptAES_CTR:msg
                                               key:key
                                                iv:iv];
    
    // check encryption
    NSString *expectedEncryptedString = @"601EC313 775789A5 B7A7F504 BBF3D228 F443E3CA 4D62B59A CA84E990 CACAF5C5 2B0930DA A23DE94C E87017BA 2D84988D DFC9C58D B67AADA6 13C2DD08 457941A6";
    XCTAssertEqualObjects(encryptedData, [DataFormatter hexStringToData:expectedEncryptedString]);
    
    // check decryption
    NSData *decryptedData = [Crypto decryptAES_CTR:encryptedData key:key iv:iv];
    XCTAssertEqualObjects(decryptedData, msg);
}



// encrypting a block of data (all zeros) the same size as our plaintext bytes will
// output a key stream to XOR with the plaintext data to give the same encrypted result.
- (void)test_AES_CTR_EncryptionStreamXOR
{
    NSData *msg = [DataFormatter hexStringToData:AES_MODE_PLAINTEXT];
    NSData *blankMessage = [DataFormatter hexStringToData:BLANK_PLAINTEXT_64];
    
    NSData *key = [DataFormatter hexStringToData:AES_KEY_CTR256];
    NSData *iv = [DataFormatter hexStringToData:AES_IV_CTR];
    
    NSData *encryptedData = [Crypto encryptAES_CTR:blankMessage key:key iv:iv];
    NSData *xorEnc = [Crypto xorData:msg withData:encryptedData];
    
    XCTAssertEqualObjects(xorEnc, [DataFormatter hexStringToData:@"601ec313 775789a5 b7a7f504 bbf3d228 f443e3ca 4d62b59a ca84e990 cacaf5c5 2b0930da a23de94c e87017ba 2d84988d dfc9c58d b67aada6 13c2dd08 457941a6"]);
}
- (void)test_AES_CTR_EncryptionStreamXOR2
{
    NSData *msg = [@"hello" dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *blankMessage = [DataFormatter hexStringToData:BLANK_PLAINTEXT_8];
    NSData *blankMessage2 = blankMessage;
    if (blankMessage.length > msg.length) {
        blankMessage = [blankMessage subdataWithRange:NSMakeRange(0, msg.length)];
    }
    
    NSData *key = [DataFormatter hexStringToData:BLANK_PLAINTEXT_32];
    NSData *iv = [DataFormatter hexStringToData:BLANK_PLAINTEXT_16];
    
    NSData *streamCipherPad = [Crypto encryptAES_CTR:blankMessage key:key iv:iv];
    
    NSString *encodedMsg2 = [NSString stringWithFormat:@"%@^", [streamCipherPad base64EncodedStringWithOptions:0]];
    NSInteger Lenc = [encodedMsg2 dataUsingEncoding:NSUTF8StringEncoding].length;
    
    if (blankMessage2.length > Lenc) {
        blankMessage2 = [blankMessage2 subdataWithRange:NSMakeRange(0, Lenc)];
    }

    NSData *encryptedMessageData = [Crypto encryptAES_CTR:msg key:key iv:iv];
    
    NSData *decryptedMsg = [Crypto xorData:streamCipherPad withData:encryptedMessageData];
    XCTAssertEqualObjects(decryptedMsg, msg);
}

// localized encrypted data corruption using aes-ctr
- (void)test_AES_CTR_DataCorruption
{
    NSString *secret = kDEFAULT_MNEMONIC_12;// @"describe omit kite parent ask type noodle casino allow bench flavor amazing";
    NSData *msg = [secret dataUsingEncoding:NSUTF8StringEncoding];
   
    NSData *iv = [DataFormatter hexStringToData:@"04a82b55518f6425030cbd17804643bd"];
    NSData *key = [DataFormatter hexStringToData:@"01d4a0c5 aac82337 beda6d3b 3958d78b 944c68d9 a0700b74 8c2419d2 3fe7f4f7 efc17222 e94603ee e6964db5 f44d4c41 b4bf182a 7a7ef43e 9d4efa04 a7669026"];
    
    NSData *Kx = [key subdataWithRange:NSMakeRange(0, kAES256_KEY_LENGTH_BYTES)];
    
    // encrypt
    NSMutableData *encryptedData = [[NSMutableData alloc] initWithData:[Crypto encryptAES_CTR:msg key:Kx iv:iv]];
    
    // corrupted the encrypted data
    NSInteger ncorrupt = 2;
    NSRange corruptRange = NSMakeRange(encryptedData.length-ncorrupt, ncorrupt);
    NSData *corruptData = [DataFormatter hexStringToData:@"428c"];
    
    // apply corrupt a portion of encrypted bytes
    [encryptedData replaceBytesInRange:corruptRange withBytes:corruptData.bytes];
    
    // check decryption
    NSData *decryptedData = [Crypto decryptAES_CTR:encryptedData key:Kx iv:iv];
    
    NSRange validRange = NSMakeRange(0, decryptedData.length-ncorrupt);
    XCTAssertEqualObjects([msg subdataWithRange:validRange], [decryptedData subdataWithRange:validRange]);
    XCTAssertNotEqualObjects(msg, decryptedData);
}

// This test shows how the underlying iv counter in AES-CTR iterates.
- (void)test_AES_CTR_IV_Overflow_Counter_Reset
{
    NSData *empty_msg = [DataFormatter hexStringToData:BLANK_PLAINTEXT_32];

    NSData *iv1 = [DataFormatter hexStringToData:@"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF"];
    NSData *iv2 = [DataFormatter hexStringToData:@"FFFFFFFF FFFFFFFF 00000000 00000000"];
    NSData *key = [DataFormatter hexStringToData:BLANK_PLAINTEXT_32];

    // encrypt
    NSData *Ea = [Crypto encryptAES_CTR:empty_msg key:key iv:iv1];
    NSData *Eb = [Crypto encryptAES_CTR:empty_msg key:key iv:iv2];
//    NSLog(@"\n\nEa: %@\nEb: %@", Ea, Eb);

    XCTAssertEqualObjects([Ea subdataWithRange:NSMakeRange(Ea.length/2, Ea.length/2)],
                          [Eb subdataWithRange:NSMakeRange(0, Ea.length/2)]);
}

@end
