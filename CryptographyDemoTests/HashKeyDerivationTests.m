#import <XCTest/XCTest.h>
#import "Crypto.h"
#import "Mnemonic.h"

// key derivation rounds
static const NSInteger kKDFRoundsTEST = 1024;


@interface HashKeyDerivationTests : XCTestCase

@end



@implementation HashKeyDerivationTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)test_HASH_SHA {
    
    // message to hash
    NSData *msg = [@"test" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *hash = [Crypto sha:msg nbits:224];
    XCTAssertEqualObjects([DataFormatter hexDataToString:hash], @"90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809");
    
    hash = [Crypto sha:msg nbits:256];
    XCTAssertEqualObjects([DataFormatter hexDataToString:hash], @"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    
    hash = [Crypto sha:msg nbits:384];
    XCTAssertEqualObjects([DataFormatter hexDataToString:hash], @"768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9");
    
    hash = [Crypto sha:msg nbits:512];
    XCTAssertEqualObjects([DataFormatter hexDataToString:hash], @"ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff");
}

- (void)test_HMAC_RFC4231 {
    // RFC4231 TESTS: https://tools.ietf.org/html/rfc4231
    
    // keys
    NSData *k1 = [DataFormatter hexStringToData:@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"];
    NSData *k2 = [DataFormatter hexStringToData:@"4a656665"];
    NSData *k3 = [DataFormatter hexStringToData:@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"];
    NSData *k4 = [DataFormatter hexStringToData:@"0102030405060708090a0b0c0d0e0f10111213141516171819"];
    NSData *k5 = [DataFormatter hexStringToData:@"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"];
    NSData *k6 = [DataFormatter hexStringToData:@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"];
    
    // messages
    NSData *m1 = [@"Hi There" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *m2 = [DataFormatter hexStringToData:@"7768617420646f2079612077616e7420666f72206e6f7468696e673f"];
    NSData *m3 = [DataFormatter hexStringToData:@"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"];
    NSData *m4 = [DataFormatter hexStringToData:@"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"];
    NSData *m5 = [DataFormatter hexStringToData:@"546573742057697468205472756e636174696f6e"];
    NSData *m6 = [DataFormatter hexStringToData:@"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"];
    /*
     224 bits
     */
    NSString *hmac = [DataFormatter hexDataToString:[Crypto hmac:m1 key:k1 nbits:224]];
    XCTAssertEqualObjects(hmac, @"896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
    
    // Test with a key shorter than the length of the HMAC output
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m2 key:k2 nbits:224]];
    XCTAssertEqualObjects(hmac, @"a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44");
    
    //  Test with a combined length of key and data that is larger than 64
    //  bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m3 key:k3 nbits:224]];
    XCTAssertEqualObjects(hmac, @"7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea");
    
    //  Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m4 key:k4 nbits:224]];
    XCTAssertEqualObjects(hmac, @"6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a");
    
    //  Test with a truncation of output to 128 bits.
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m5 key:k5 nbits:224]];
    XCTAssertEqualObjects([hmac substringWithRange:NSMakeRange(0, 32)], @"0e2aea68a90c8d37c988bcdb9fca6fa8");
    
    // Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m6 key:k6 nbits:224]];
    XCTAssertEqualObjects(hmac, @"95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e");
    
    /*
     256 bits
     */
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m1 key:k1 nbits:256]];
    XCTAssertEqualObjects(hmac, @"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    
    // Test with a key shorter than the length of the HMAC output
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m2 key:k2 nbits:256]];
    XCTAssertEqualObjects(hmac, @"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    
    //  Test with a combined length of key and data that is larger than 64
    //  bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m3 key:k3 nbits:256]];
    XCTAssertEqualObjects(hmac, @"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    
    //  Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m4 key:k4 nbits:256]];
    XCTAssertEqualObjects(hmac, @"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
    
    //  Test with a truncation of output to 128 bits.
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m5 key:k5 nbits:256]];
    XCTAssertEqualObjects([hmac substringWithRange:NSMakeRange(0, 32)], @"a3b6167473100ee06e0c796c2955552b");
    
    // Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m6 key:k6 nbits:256]];
    XCTAssertEqualObjects(hmac, @"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    
    /*
     384 bits
     */
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m1 key:k1 nbits:384]];
    XCTAssertEqualObjects(hmac, @"afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
    
    // Test with a key shorter than the length of the HMAC output
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m2 key:k2 nbits:384]];
    XCTAssertEqualObjects(hmac, @"af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649");
    
    //  Test with a combined length of key and data that is larger than 64
    //  bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m3 key:k3 nbits:384]];
    XCTAssertEqualObjects(hmac, @"88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27");
    
    //  Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m4 key:k4 nbits:384]];
    XCTAssertEqualObjects(hmac, @"3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb");
    
    //  Test with a truncation of output to 128 bits.
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m5 key:k5 nbits:384]];
    XCTAssertEqualObjects([hmac substringWithRange:NSMakeRange(0, 32)], @"3abf34c3503b2a23a46efc619baef897");
    
    // Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m6 key:k6 nbits:384]];
    XCTAssertEqualObjects(hmac, @"4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952");
    
    /*
     512 bits
     */
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m1 key:k1 nbits:512]];
    XCTAssertEqualObjects(hmac, @"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    
    // Test with a key shorter than the length of the HMAC output
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m2 key:k2 nbits:512]];
    XCTAssertEqualObjects(hmac, @"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
    
    //  Test with a combined length of key and data that is larger than 64
    //  bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m3 key:k3 nbits:512]];
    XCTAssertEqualObjects(hmac, @"fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
    
    //  Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m4 key:k4 nbits:512]];
    XCTAssertEqualObjects(hmac, @"b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");
    
    //  Test with a truncation of output to 128 bits.
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m5 key:k5 nbits:512]];
    XCTAssertEqualObjects([hmac substringWithRange:NSMakeRange(0, 32)], @"415fad6271580a531d4179bc891d87a6");
    
    // Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).
    hmac = [DataFormatter hexDataToString:[Crypto hmac:m6 key:k6 nbits:512]];
    XCTAssertEqualObjects(hmac, @"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");
}

- (void)test_PBKDF2 {
    
    NSString *password = @"test";
    // password and salts to use
    NSData *kSalt224 = [DataFormatter hexStringToData:@"77f706c5efecf3bd98aa2647c60820c088dce942bcb77905d436bf4c"];
    NSData *kSalt256 = [DataFormatter hexStringToData:@"601b326a6e2f5ab48907ff13e474939b55a7e9d448696c0febd4621208715222"];
    NSData *kSalt384 = [DataFormatter hexStringToData:@"97cb5258847fa14b3359348dd92c0683f92258c1de097019b00c3a97be856abd9d20e3cbe258aefaa4359f7cbfe8e52d"];
    NSData *kSalt512 = [DataFormatter hexStringToData:@"929f5b4b0531dc7c4d31bf51372cd7b867701367ba832b41adb421aecdd081e8ba32b4f0c4dde9ef6c6f272865dff1ba6dbd19b5f62ed798f9c2fd4e5ad91a77"];
    
    NSData *key = [Crypto deriveKey:password
                               salt:kSalt224
                               mode:unknown
                             rounds:kKDFRoundsTEST];
    XCTAssertEqualObjects([DataFormatter hexDataToString:key],
                          @"786eb4720a58b3fc1f46e174e1ffc96791273a7e8d26a68e1208e83b");
    
    key = [Crypto deriveKey:password
                       salt:kSalt256
                       mode:unknown
                     rounds:kKDFRoundsTEST];
    XCTAssertEqualObjects([DataFormatter hexDataToString:key],
                          @"23dc60632245ee72211d7851f7dcd010cc5b6428c34518689b564662356cb374");
    
    key = [Crypto deriveKey:password
                       salt:kSalt384
                       mode:unknown
                     rounds:kKDFRoundsTEST];
    XCTAssertEqualObjects([DataFormatter hexDataToString:key],
                          @"7a9448f51adf6ec40ca6d69d40a8205bee760e32aa0880c2b48bd05f8517f54a0e073fab6f9a4579feb9386e9a68330b");
    
    key = [Crypto deriveKey:password
                       salt:kSalt512
                       mode:masterKey
                     rounds:kKDFRoundsTEST];
    XCTAssertEqualObjects([DataFormatter hexDataToString:key],
                          @"866749ea6c2c28e0e4bfebedf9a48b3d619a08536917c33a518e82767b951e06d8fa7558190c04f32e5b3cf1eff9b21ba5604e1e397888603c49790da8d22489");
}


@end
