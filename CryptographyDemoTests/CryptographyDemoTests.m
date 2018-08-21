#import <XCTest/XCTest.h>
#import "Crypto.h"
#import "Mnemonic.h"
#import "KeychainWrapperMock.h"

@interface CryptographyDemoTests : XCTestCase

@end

@implementation CryptographyDemoTests

static const NSInteger kKDFRoundsTEST = 1024;


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
    NSString *hmac = [DataFormatter hexDataToString:[Crypto HMAC:m1 key:k1 nbits:224]];
    XCTAssertEqualObjects(hmac, @"896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
    
    // Test with a key shorter than the length of the HMAC output
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m2 key:k2 nbits:224]];
    XCTAssertEqualObjects(hmac, @"a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44");
    
    //  Test with a combined length of key and data that is larger than 64
    //  bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m3 key:k3 nbits:224]];
    XCTAssertEqualObjects(hmac, @"7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea");
    
    //  Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m4 key:k4 nbits:224]];
    XCTAssertEqualObjects(hmac, @"6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a");
    
    //  Test with a truncation of output to 128 bits.
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m5 key:k5 nbits:224]];
    XCTAssertEqualObjects([hmac substringWithRange:NSMakeRange(0, 32)], @"0e2aea68a90c8d37c988bcdb9fca6fa8");
    
    // Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m6 key:k6 nbits:224]];
    XCTAssertEqualObjects(hmac, @"95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e");
    
    /*
     256 bits
     */
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m1 key:k1 nbits:256]];
    XCTAssertEqualObjects(hmac, @"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    
    // Test with a key shorter than the length of the HMAC output
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m2 key:k2 nbits:256]];
    XCTAssertEqualObjects(hmac, @"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    
    //  Test with a combined length of key and data that is larger than 64
    //  bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m3 key:k3 nbits:256]];
    XCTAssertEqualObjects(hmac, @"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    
    //  Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m4 key:k4 nbits:256]];
    XCTAssertEqualObjects(hmac, @"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
    
    //  Test with a truncation of output to 128 bits.
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m5 key:k5 nbits:256]];
    XCTAssertEqualObjects([hmac substringWithRange:NSMakeRange(0, 32)], @"a3b6167473100ee06e0c796c2955552b");
    
    // Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m6 key:k6 nbits:256]];
    XCTAssertEqualObjects(hmac, @"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    
    /*
     384 bits
     */
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m1 key:k1 nbits:384]];
    XCTAssertEqualObjects(hmac, @"afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
    
    // Test with a key shorter than the length of the HMAC output
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m2 key:k2 nbits:384]];
    XCTAssertEqualObjects(hmac, @"af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649");
    
    //  Test with a combined length of key and data that is larger than 64
    //  bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m3 key:k3 nbits:384]];
    XCTAssertEqualObjects(hmac, @"88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27");
    
    //  Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m4 key:k4 nbits:384]];
    XCTAssertEqualObjects(hmac, @"3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb");
    
    //  Test with a truncation of output to 128 bits.
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m5 key:k5 nbits:384]];
    XCTAssertEqualObjects([hmac substringWithRange:NSMakeRange(0, 32)], @"3abf34c3503b2a23a46efc619baef897");
    
    // Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m6 key:k6 nbits:384]];
    XCTAssertEqualObjects(hmac, @"4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952");
    
    /*
     512 bits
     */
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m1 key:k1 nbits:512]];
    XCTAssertEqualObjects(hmac, @"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    
    // Test with a key shorter than the length of the HMAC output
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m2 key:k2 nbits:512]];
    XCTAssertEqualObjects(hmac, @"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
    
    //  Test with a combined length of key and data that is larger than 64
    //  bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m3 key:k3 nbits:512]];
    XCTAssertEqualObjects(hmac, @"fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
    
    //  Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m4 key:k4 nbits:512]];
    XCTAssertEqualObjects(hmac, @"b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");
    
    //  Test with a truncation of output to 128 bits.
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m5 key:k5 nbits:512]];
    XCTAssertEqualObjects([hmac substringWithRange:NSMakeRange(0, 32)], @"415fad6271580a531d4179bc891d87a6");
    
    // Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).
    hmac = [DataFormatter hexDataToString:[Crypto HMAC:m6 key:k6 nbits:512]];
    XCTAssertEqualObjects(hmac, @"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");
}

- (void)test_PBKDF2 {
    
    // password and salts to use
    NSString *password = @"test";
    NSData *kSalt224 = [DataFormatter hexStringToData:@"77f706c5efecf3bd98aa2647c60820c088dce942bcb77905d436bf4c"];
    NSData *kSalt256 = [DataFormatter hexStringToData:@"601b326a6e2f5ab48907ff13e474939b55a7e9d448696c0febd4621208715222"];
    NSData *kSalt384 = [DataFormatter hexStringToData:@"97cb5258847fa14b3359348dd92c0683f92258c1de097019b00c3a97be856abd9d20e3cbe258aefaa4359f7cbfe8e52d"];
    NSData *kSalt512 = [DataFormatter hexStringToData:@"929f5b4b0531dc7c4d31bf51372cd7b867701367ba832b41adb421aecdd081e8ba32b4f0c4dde9ef6c6f272865dff1ba6dbd19b5f62ed798f9c2fd4e5ad91a77"];
    
    NSData *key = [Crypto deriveKey:password
                               salt:kSalt224
                             rounds:kKDFRoundsTEST
                                prf:kCCPRFHmacAlgSHA224];
    XCTAssertEqualObjects([DataFormatter hexDataToString:key], @"786eb4720a58b3fc1f46e174e1ffc96791273a7e8d26a68e1208e83b");
    
    key = [Crypto deriveKey:password
                       salt:kSalt256
                     rounds:kKDFRoundsTEST
                        prf:kCCPRFHmacAlgSHA256];
    XCTAssertEqualObjects([DataFormatter hexDataToString:key], @"23dc60632245ee72211d7851f7dcd010cc5b6428c34518689b564662356cb374");
    
    key = [Crypto deriveKey:password
                       salt:kSalt384
                     rounds:kKDFRoundsTEST
                        prf:kCCPRFHmacAlgSHA384];
    XCTAssertEqualObjects([DataFormatter hexDataToString:key], @"7d485ac94193b49c4340f6c156c5d8ad61d52e0c07a9a4821269762171a7569e9996e13564f44741bf56b2a3166aea97");
    
    key = [Crypto deriveKey:password
                       salt:kSalt512
                     rounds:kKDFRoundsTEST
                        prf:kCCPRFHmacAlgSHA512];
    XCTAssertEqualObjects([DataFormatter hexDataToString:key], @"866749ea6c2c28e0e4bfebedf9a48b3d619a08536917c33a518e82767b951e06d8fa7558190c04f32e5b3cf1eff9b21ba5604e1e397888603c49790da8d22489");
}

- (void)test_AES_CTR_encrypt_decrypt {
    
    NSString *password = @"test";
    NSData *message = [@"hello world" dataUsingEncoding:NSUTF8StringEncoding];
    
    // salt for KDF
    NSData *salt = [DataFormatter hexStringToData:@"601b326a6e2f5ab48907ff13e474939b55a7e9d448696c0febd4621208715222"];
    // derive
    NSData *key = [Crypto deriveKey:password
                               salt:salt
                             rounds:kKDFRoundsTEST
                                prf:kCCPRFHmacAlgSHA256];
    
    // iv for encryption
    NSData *iv = [DataFormatter hexStringToData:@"e3a982494277626b8eacc3d6a750367c"];
    // encrypt
    NSData *encryptedData = [Crypto encrypt:message key:key iv:iv];
    // check encryption
    XCTAssertEqualObjects([DataFormatter hexDataToString:encryptedData], @"ef970bd5d01d868c5e2314");
    
    // decrypt
    NSData *decryptedData = [Crypto decrypt:encryptedData key:key iv:iv];
    // check decryption
    XCTAssertEqualObjects(decryptedData, message);
}

- (void)test_BIP39_Entropy2Mnemonic {
    
    // 12 words
    NSData *entropy = [DataFormatter hexStringToData:@"0c1e24e5917779d297e14d45f14e1a1a"];
    NSString *mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"army van defense carry jealous true garbage claim echo media make crunch");
    
    // 18 words
    entropy = [DataFormatter hexStringToData:@"68c47602458957c948b89702721f2d40012f64bb94e51e61"];
    mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"hand casual letter mention nice tool carry base act movie slender length base rather unusual original bunker another");
    
    // 24 words
    entropy = [DataFormatter hexStringToData:@"2041546864449caff939d32d574753fe684d3c947c3346713dd8423e74abcf8c"];
    mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"cake apple borrow silk endorse fitness top denial coil riot stay wolf luggage oxygen faint major edit measure invite love trap field dilemma oblige");
}

- (void)test_proofOfWork {
    
    // init challenge
    NSData *challenge = [DataFormatter hexStringToData:@"ab436ff422f54c852829a63ab325791c001de60ae4ea934ad8a603cc5eab3129"];
    // number of leading 0's to find
    NSInteger difficulty = 4;
    
    NSDictionary *dict = [Crypto proofOfWork:challenge difficulty:difficulty];
    NSString *proof = [DataFormatter hexDataToString:[dict objectForKey:@"proof"]];
    NSInteger nonce = [[dict objectForKey:@"nonce"] integerValue];
    
    // verify proof parameters
    XCTAssertEqual(nonce, 35559);
    XCTAssertEqualObjects(proof, @"000024b20de5f9375254af627f76c47fa93973f3442bfbe42e9fc8fd9cc969c6");
}

// Testing a lamport signature requires us to create the keys deterministically
- (void)test_lamportSignature {
    
    // message digest
    NSString *message = @"hello world";
    // key/hash length in bytes
    NSInteger klen = 32;
    
    NSData *digest = [Crypto sha256:[message dataUsingEncoding:NSUTF8StringEncoding]];
    
    // 2 x 32 x 32 bytes of private key data
    NSMutableArray *priv_left = [[NSMutableArray alloc] initWithCapacity:klen];
    NSMutableArray *priv_right = [[NSMutableArray alloc] initWithCapacity:klen];
    
    // 2 x 32 x 32 bytes of public key data (ie. hashed private key data)
    NSMutableArray *pub_left = [[NSMutableArray alloc] initWithCapacity:klen];
    NSMutableArray *pub_right = [[NSMutableArray alloc] initWithCapacity:klen];
    NSMutableArray *pub = [[NSMutableArray alloc] initWithCapacity:(2 * klen)];
    
    // convert the digest of the message into binary form
    NSString *digestBinary = [DataFormatter hexToBinary:[DataFormatter hexDataToString:digest]];
    
    // populate arrays of hashes
    NSMutableData *KLeft = [[NSMutableData alloc] init];
    NSMutableData *KRight = [[NSMutableData alloc] init];
    
    for (NSInteger i = 0; i < digestBinary.length; i++) {
        // deterministic creation of keys (even and odd nonces)
        [KLeft appendData:[[NSString stringWithFormat:@"%li",(2 * i)] dataUsingEncoding:NSUTF8StringEncoding]];
        [KRight appendData:[[NSString stringWithFormat:@"%li",(2 * i + 1)] dataUsingEncoding:NSUTF8StringEncoding]];
        NSData *saltL = [Crypto sha256:KLeft];
        NSData *saltR = [Crypto sha256:KRight];
        // generate private key byte array
        [priv_left addObject:saltL];
        [priv_right addObject:saltR];
        
        // generate public key data - hash of private key data
        NSData *pubsaltL = [Crypto sha256:saltL];
        NSData *pubsaltR = [Crypto sha256:saltR];
        [pub_left addObject:pubsaltL];
        [pub_right addObject:pubsaltR];
    }
    
    // construct left/right pairs of public keys
    [pub addObject:pub_left];
    [pub addObject:pub_right];
    
    NSMutableData *sig = [[NSMutableData alloc] init];
    
    // generate 256 x 256 bit signature
    // for each bit in the hash, based on the value of the bit, we pick one number
    // from the corresponding pairs of numbers that comprise the private key
    for (NSInteger j = 0; j < digestBinary.length; j++) {
        NSString *bit = [digestBinary substringWithRange:NSMakeRange(j, 1)];
        if ([bit isEqualToString:@"1"]) {
            [sig appendData:[priv_left objectAtIndex:j]];
        } else {
            [sig appendData:[priv_right objectAtIndex:j]];
        }
    }
    
    NSData *condensed_signature = [Crypto sha256:sig];
    
    XCTAssertEqualObjects([DataFormatter hexDataToString:condensed_signature], @"0f8b434d125b6a388a8e6f949c0b673dade6d0b4f3a210abb9b1720256811b0f");
    
    XCTAssertEqualObjects([DataFormatter hexDataToString:sig], @"5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e93fdba35f04dc8c462986c992bcf875546257113072a909c162f7e470e581e27866a3c6db23417d04441d223f67bdf73a5f195a03db472cd55c14388756ceb506ce44e96ecfd0004515dd4a73f52b742e680ea8410952f513b28472aae600cc3fe8cbea0e8ca33f7656bab25f65f11f382bc464a764a9d9d7096d8d22983a0df1aa67adbe8ea578edb50b764bc8d69a90c82aaf1797b6a200808c1ede7ae8e8ffa0ebfa3469b11a636ffa795cde65317ee329b74fa53c73ead1f0b607c50881dd37db493b760de8ebe42cfaa9579d30d2d340a09f18b9087eec4de572b9984bdb3877f68eff69e8b4b9c33a75742cde06463fc2f14b7f7db521463cdee315d4e6bf337fd107d104a503556497b9b30acd650278c8745efdfc2ecb4340cfa3732bce38927f44b407f2847978c408676f9896dcc88976ee49e7a6fac83aa1744e0f13e287eb62626c88a56cc00af930ccfc8e6aae7c48ab22745b34a1b1a6ab67f500f4d0f4d7eb701d93673342fcbc355d1dcf6135c141ad845e98c8e856c39204ed1f8f8c1b9cec828c9f0d43f7798e01f9041c20adcc3f2d81f318a481dd7c41b8b72b0e7d86036e6c2fabbf51144f4066a1106d7b6cf091e9eef8f7abbce971d61135a96c7de69f3ab40c3e5df693a6fa9f4732fc1dfb76d55c6846956fb4f6c37c085a06070136387c009508c50871a646cc95ec388bcc29d5662abe8a6866e41ccd363e03b84038768cb9f69855901837bcb77b85abd2fe23daec4f89ed4ed8693aae386b82503697ad8c3ed39a6a37be69653ca1f1252175e59a31e897ae917342ae1e9fc836e57c7ef23910f39af1ce7dd68b5305fa57d1876c60dd5a21bf78b8305e0f25fda1c09767a7d1bd184aeb1dfbd6b00f1b617e05d2c640e5883a3a93a4d7a4aabf7722a39e30e243439415de71c7cfd1cf358bc709292b5a04a28aa3cf776010cddfbd1868c5ab6ea202b82b0a0c326358b8cc44996ff5fa3adda51e3fea0709b73a6e23d820766c10279237946a936526fe05925639af26dfed85a6180960cdde2232f7513f57a9bda8add3f7f77a663cd2a3de9cc1221f8a2fa9ed47b029f811297a9fcc627e701197a3435028c9e0d26d6aeab9c590e85763dbe7664624b2a5638671bf19f4067f9b2caa4a72e7872db84da8df9bd8edf234018dad3d409ed4b309c534a58cdd1921d4bf7baf20e2c9f1590bd583396af9f3b1f649ca344e9feded6d7dcbef32a09d7805ded1c69386cf115b19a6bdba2773bccfc9af041f5a6566876ebf84c38a7043fc0da1339f231efd207cf5b13266c3a68d03c1ed7418419d040203c61b99f67e5ee248b463395c1da2ea2968fe65a7726f4b411a4ebe9b7252252e59a2c5ee24aa95272474543c56a0ee1390e413447bbe36531a74adb9d7b91feb21e90a356bce506ddd46a64e4d1373edb18a1f8312ab8dee76b757c3c37b1310ec969bb69a4aac3d260f519fe5f8d752ab958f446e1e8d435a28c1f5a53f6cb281505131a324047ec31bc87a4ac3537bfec4a3b00f974ffdb324763ab1ad0c7218c8e3099c0728561a7e5ffadaf52e68858c6680e9fc1adcbd1f2181de96258f15247717ab9d274829847a02ff8cb0f5be7d69cf818797545de55df697adad9438daab9df3b375c6eda19c25dd711b96160d298a49e39e81966d314a4f7871ee42e9bf0acc790f3997ac79c7580b80cf7dced40306329285ea0a226dc93d9768053392f99910ece810e4dc8389266ea0c136ca15f04fc86bc01f108e115fd42b7e41057a8f3b50f41a51828c5618663aa4a91f309646e08a071a9e9ecfcf1780cda2d3c0b3bd965c67f51851d4bd6a1869b9cb354001d79a3bb25d9fa7ceee8cd2a59358cbc10fa88112e2c0eba6c4214e35fdb63a374e36b85386339222961dd55d76b67ca211b3cc4d0b160e25933a365cad28c9d32cac71463e12874dc976ab55954494967c1971c2a81017b21a5ffa16b84fd53d5bfbb208479217b56def58ed4eea630bdd104eb4b2ce5616cf1da14ccdb7727f285982cb96f99c03176a2d7bbe66041b65bf49e59a120e4d509ee3000a366fc7b10ab23412711db9718fee5d5323e2647702a1785a3bd4376ddbfba483acbe00187b65df6315502c0f3d8ae4916ec014f9639a2fa1162ebad504ffe8af875065c56c503d0603f897dd9ac37760f6a78fe6fe953977203580caf0ab211bccaba48165bbb7fcf90bac803b1eef12245b9862cf3e6206b48cdbe5d63913533edc342cbc129b2e11280a149339d76c05e0fa646b154c74c8dfdd6f994d83affff625180eb7a3707fe6810914cb8bb6891d995d0f24e4fcefd628032a3296f035cc3a82ea21a521b95a0f011061e1c775d23adc81f72ab9fca3af0bd8db720a29caa4adaeee2465dae8baf8e3f8a0b6178af769046c433aa81177584fc7e5ca0d12b04ee10cd631fb3859acd5a4f59fb66d0a88ab981714aef0d29cfff242abb9f7663eb5451d3e634401eb611c71eca6bb2c0b90be7aa73186f0042458d21096aa373cc545b174ee96654ca48eaf25daa4bffd68ce2e20272181ca93e902a39535e6fc8144800aa9af5901b81505392ce57f897c54e4e09cbdfa111276a6f0958ea6ac0aaa7dfcdbafe6b80dac7a8dca6635fc9469a2e7e4829f1bd6f50beb0abd3a1fe5bbbc91ac85e09233c3e763d6527a3eb49e31a3586668e7b473b564b739aef3f847dcd87011159f189bc55cb6b610c824f8c9c9651c6d9fefeab9c36fa29059d476176e2654536832dc1b2bacd908164bf95db99357a5d592cd26830d42f32dc7cdde18240ad36e2ea4c75ae4ce27b1d9244a5cf7a1009e49d389574e43a901186dd42bf603303af84913ab159c59a46539eca564a608f14155c54fcd6265ccd076d4dfc6c202d2fb70fbdf0dd3bf2ff87eb0e1481af770d26f17a4e97ed0d5d7725b456a7491b42b6e16b680d974b94ad11d3ea5befe0b4ab9e5cb64507a13079923fef2da9e63148d06bf0feeef00d2b1830169f0cdd15e5f1bb00a790b2f8a8d1ebaecb3969282b6d7dec4636ef92055319651c7d63f184f743023e73d81a515e4b7b7743f0a58843f80e4133d8ab781b6fa29a7dc8e4bc98fe6b2a4853857d9b1ada585ba57810f7e3b1ea5ee36a5bd634cd6c815898b96e5ee751d95b0d8576af8953dd26a081d29d423d38fc5cad293bf4effcdaf86a7e6617100b6bf556a878108b2cad3b9d1d0a07ea90086a076a27940dc9a9a005af8418d0444fc948a49a82abcf535e6584a1e357f6ed160970c50ae29f4a0c67d7075f2f97b810953a8e488ebb722b7475c56ad19bf4456e5a39a335ae55d799c938a6787a32d6cacd4215c82aa42218130b6e11ad94222bfd4013ba83ccf1aaf6c8ad47fa36cf57882ef0453ee879fa2c7bcd6db206c6abfaa5edf1dd269b32d2416ebcbf4ff75aea282a3ae7bd5aee7c64e406e58fb2f356bfcbdfa3a5090bc96cdee1f8fa4091887232486f2e3b39398e7fc6e255471c59391e6f8f1d7c44e773161748dfa281d9fc0ef1d47b5c4cf642b270964da03549b18a924852881d3d92a73f842b37c321923db22cdd94aea4cc18539ef1e165484373e4ff34cb293b5f11a1f4c41829554751a5826efa0ba97a2b5cac0f61b5655a22f224883d3d3adc34f3aced562fb51ba81e5d36b6f93a2aa58ddb4f4bd5fedd3591db46be99a608d0e1dc31a52b927b7af660fdbce4a5e7ae4d8f71606b1fde20f598ee72f595fae0e7562658d3b0cbe55ba61e45938fb274d5cef2cf02a9ac607f6548efb92e284b29f49cebce9dadbbcefb7bc8a045681a10635bd07d25f3abbb45171c9b83c15e43a5b4d452253035a3760b49d70eedb4f0413b86576b1f71c368da588eae699fdc8b018259b58c6c06fa6143492bc4274af976ff01648a3744b17cc03093aef5fdc8d33f1a9c884cfb7b5c4e00f67738d6dc32a3bbcac2be9279160d659e0d40d576d86a6ad8e739f1abcdb35dedd660f021bcbe928203240f9c12d2f4693ac3806e75034f404ae0e008348734e99d1019b9f8b2c26e71e092e5e1961a305b87df39b2e17b8ecce8004aff14a0ac32157b22db53dd5979b3245203b13bd6a9dc5711da8488bc4b85956bf6aeac449929ba7fd949cdb2702939dd32af0928109737bffc6ac8254f42b180b1d94fc983fc62e204cc1f6d48e95905084ecba7820d5e3065b729e13ff5476876510f3d8bcee914845c76287331bf540a9708831c9a57fba3d0e676cc97c73985d13cebd8cd73afe82f814529e0bd8f004c2e85d667e8583fc9c746ec7572815dab8f6cbe937ecb15ee96443e635d843a822cd2a14994e71b7dd88631098252c4976cddb439b5dffff23d1fd86860de0db66500f9a9b3097afca2602d1a1ae5afc987fd645f7b48f3dc530a69e5d28f18f5aebf95251040c98f17800ec1fa5bd531edee2f49fe59d377c972e80621bd914fa32378f580cd7291f8bfd0873ccfa31ebc8a99a02b8c43bd897c67e83fd117a85b8cc2a3f2437961f475fff248c5b17c5b041675a596213fec338e3892111410a82eb12a3e4ddf5fd8faac3b29794c8682c374e8bd08d4a9632c1e619182198f01644763c3473d5220a540b3d058e0f6caec356c552fca3017d8e4d7c6a08bf89577b1cb25ea993699c56dab0110cbb2f9948a5536fbeec03b0da5d70dc8311f2b2ae156dd30e746e6f80cfad0f4ee4b591803638d065dae7be3944464a42023d3a01fb5e8fde17b4c8bce4edaeb558fabbde8e0d1630de2d5b560abbb41b73dda15ff7ee59f130181539d93d453106852f2d1771614ef04118452d370d0998002212023662b94632159f757ca96fb421caf8470973fd211744102adc55989c54d8b038af97d0d73e8adfce97384767cecf7625ebd3d02c946cd225646bb0eb8090ded3965a3931c1b18f0c037f82b618059424e7fe9bbb7cefe6a8a38231a8260d87794a464db8c20d2394366f50fa5407236f02e9fd4e21bf36db9258cf4c272bf6a1617ce01d3fc31182da5f4432b31356e7b192b5bdf4b01aa19df8875a18e0c1e77c2eff5ae154ee3bb7a1e764d1bfaae8d4694e74dbc83161934226b943ac45f890acc0db95f69a30e6677ea46f7e8c9d59ab34c8ef4ef4036f1036757e527eaca8ec802a2d26df25af3cc4bb43c31535a046b001533063a4b1400831a6adab158496c783bd9a3f593e67025de280733656f28d89021dbd07bd37bc410e0e108fd413da7ccc10d0d6ba20aac757d9d8dd600d7e11e6d59414c3b1229c66b3b692f2b7d6de2824282fb1bdf94409cc8b0774d7f87e87e1fe215a8daf572d402026bf7e01042a445aec6bafa87c80a107522f4df13d48cba046a5537289dc7bc8ed031de25a0b75e773590ec21ba670e3cbe678f496f811c3857375f46fba3fb7be9f79292b9a4350a03ad55038a907d21ea8914b388bd7cb9805c44a2c3eeca77139dd3e081e20f43f2313451e1f88b1928e06f366af42888fa328f3d2c2f72720fa7989d414ec367be73adb2208ff97a1e71a8a1afeef574a09dddc3fe7bde29e67c03c290b43c628e63b35f4fa9103cc58346efcda584acfb250d8f51b484e378b481315231f19816217cf5a24899bbf8e7adc0ef630330a8575434836d34aedc230f0680c13481e0ce717c7b8776523dfec38dbf9893c3c7ba56fecd715397b13cf909e0650b653ad6808159db91ebabb83e2351057ae0cbf19ad158f301c1401b85f2bbe3dff9985a6afab2f4a8ed47dd5da0ff995d3c268dca5e944d6a84e8af24055972807c000838081acac2f54228c8002a707cb784652eae9d466186b2a93f3a496cf9e58b0da16654a0ce1408547d2d1b353a4ee923b4f50fb3b3004037cdcadf509af7a95d8cd9bf6c63168dfeef91ba98da46ab45199faeb35b8ce5f6133d7e93be1eb88d2b9c817fae88d86128ba161f29076696454838abb4a4e4adbdb1269af28328e505d0fe0de138749e4b04d519c7dd36512e724cdc8b8b04f718fa30d7d810616e45a4257f3cd3ea10bd836e129e4f7c2404c317283bc5630a73acb16068136ffe6bef0752e90fbaabd7bca23125d7d9cb3e140394833e7625e7305b9a7d5f82793854553ab85fecfb0db114bfce41b67e142959bf9c1f426a5e3b711460058d682f2150c923cc9b5422412f82145ea95934d76b6447fef61d59379fdc82528274125094bc320f105350b7b182cfbf8680777e659ef4beb8de4d053d25351ff431cae959289801735f5675ee1416eabddaf75efa2dea10c226dc405a62e526bf92b7b73191d5faacda09d9b354df2500e6612233bb0c072d8c2e7f1cb34cf01400695470aff8047695a825e4afd81e215ff6b5725077eb65ab08bf624ce738016829701ac6cd6d1e5fa317c1ad52102e6262fee68c20f14b3e66976f1ffe53a66964b955a69af038e7971b486072afebbd1df4c712f8348c4e41dd9c9d999a8b29a98b47b7c6ba410a413e62e0da01064b4ec191c859959c24522ee3eae02b03c29d7e443f7b22fb7aa212b784acdf7e260e53dca6e58c78bae6a65dfb1bc1d8d46c322184b79e7e3d9e2d5adcef899672eeda85ec38f4e877e22366c9e60c880ac7d2c4ffe7b36a92f8a27b38e011ceb164a94b142e34e0a7604fb00cbf284425af47fda523b037102201eb0872e3cd871aea94da16583fff1085363faab12381a0de2b591399038154ef3237e9d719ef6564a892c18f21fb6ea0110a6f567424d13a1911ab4cd0fb74ea3e30a88037b60fd91622642b5c77b9226c74fb9bb2e2e70ff9869adf7dc03a5188e8ff2f34bedb26b5db668a9e6693f1c7ddc551279a616fe4802988659882ad3488f97374b95d54ff3521b1b25000beaa3d5476cacce8fc8e1214bd10d66edd2c667ed627425b1b93fe00e9f8ae8c031384d43387275907f1b9d03f6cf78e6c01ac70764b1b224b819ed5c4d29522e4cb903dffb48ac8997c67a914a7f42d4ef7c00fb9c66981dd06ec0b178523ef700f14339807dc4a4993fb19249b8cdedc8e1f0e115529858989a15bf41bd7fe0994c7683646021369110732bf437b510cba75d48ab89307cecfe802972cf1575792a37522245737eee629550af995f8ddb89802894e8dd04ad9551801bc0733d61d7f2e40d1f59cf12fb5bfa1fd9f5272a266d5a06fdce773d01e30dbf4cf0722ff4154c34b1ab81b7ad936da9d6c53117e7e0d313475cbf77b0c49c47efdaf1d410a9e455850956fde97ab4c58dfb49ad6cfdc2b0088d4d7bbeff1430a6bf681411f8ef3d9954bb2fb787ae73652d28a1f00bc893cb1b25edc7b5b5ba4c1da2084dbf32d1dff382adecb7e4834e61d7c73aa9681a1c75396470e45e8891d3e39dd081c161050485245639ff7edbb3a962cda24ef5393b0ae7300c87bf0dc2306acde5cbf30b36db5937f7ff2c14d6ec3f22e6210e9ab3424a9de3fae5049759def5b584e7b851a876a370ef9a9faaaf49a523935e799c888ff18e419aa5cf48ad3cdb558e078c77784cb8ab95cea9758f0405c22e36d8d265966a7f336ce6ef93ccc12319bda00cac67df0948114c9af327c151a011e77db907945bd167cb0da1b87ee3b646a0ac20418866de73ce4d03b1edcb05abb41c2645afa076783032d4b0d53ce739666b7065fd38eeea753fccaba3a5a3cac55830a96f9a00a9e8fd3eb93646b5deb0730c133f8d2d2e51b9b26ebe7d99f696ce7cae93f5ce74c064b1178be1acb246691c6c3374a3ccbc242836574105dbc649a0f38321d65e42c77e637eee003f64afdc501872d21a56167500327fc6e5a681c44dd2f0af09788b61ba01d50a3057f41ce267f96140e6ada4fc462859eb532e16d827d1d007276983a41e21cb0f562c79b46b5ecab299fb89b5dcbe778c7cb7965153205cd46b647aa0c8247732dd5decfca7ec855af6e1edc5fc22ed0acb903aadb595f87f1582e87c8f066759d82c5ff6cb765728f4a4617a2a85c1fdaabd4db5a33e5015c72875bb97918fb5d68b62b1665a3ea31536f7ee75a324d3194abfe205aa7c63a56e759d8c166a78f177abc44fa49427c068b7a9ea2dc48b2677c3a0c2008b4e725b721f9f099b51c1c260f3f392db1be8a2cf5916f837b926ed1db8bdd9601cbea0c52ec669f70ca9a3424c38775f86d01954d787ce1a3aa7735173bfa1f2aa3cf90e47d19d73cfb9737ae581ea1074ad4797ae883f13a4646c75d9b52a6aba6ba78c551a018362c3ff6ed966da28efd77b3723a46e4d888fab478976fb9b718c9bb5e9f497893b22a2b1e35ceccaa671bd29b3cd5fc2b896b14a5769c9028efc513b628867c2cbb297f279776ea264312e5f983feb2379d2c959ee0a9d07a0e0d839c7e265bbdf3816180de9d44bf6c262fb5b440b8892129260ba4d88ea18ac70e961d19ea28efa13be712e43cc17ade8919c823f6314f5cad5555d1c24c517373c2ba4cbd4b49770e6b959ef68bdfba3232b962c37c66403281b92b700b6d7455fc135ea578b954607b75a9cd95458585e99bef6f1634ec2b76a74201bdb45e3ac288113eac29c2be7c02f63110d513ea8f68daf56ac92d4514b09454c570117d13e54ea94c5845f1b5d22d3cd3958930a85c6ee609ee37715fe82150d3d91b15012a152234d6fb927d89e8098eefee74084e9ae04ea115b51bc7ac3796dcb5415f514965b272af28c12d832305801e090b59b625f750f1c2e90260229e2bc3dc35f7da58988df68eca14d91bb1d3a6e927a1509ae2aa4d6be092dcd4e2a02b8014b325c73773885f05c0b71073bd76625210ba582481a81a9b0b3742ad5ddc0fca936748d07c66b890cfed30d2ef55fdf3a9b65ece47b8a882bc9fd2da3a8a499f50f13d50b40ff00898ba3981e19cbbc5beb7f1b1a4e342a37c27d04b8218563f6923a66893b5b8c1a9ca2c1d3a45e566837127c214ba795f282fe04392e9ef5f0bacfa8dfcd37d3e83d45a1006776ebb239171d8a466ee3f208b3279bd6c4b519be6bae9f5fb9159ae50f3a5e959d75686f00ecbfd594cf80020ff904e7bb07ceb5fde413bd0ef54c172ebb0580ab64ea334aa8fc69d62ace3cdcaccf0646ec0cbf3735c0158ee184d2a5ec26a15d255050e187f016e1b7e9857794427b3f4a41c0b2bcc4177e8d78997b86963196a40115dafd2c4e27028b4602405728414e2294aa33d578efac482e87649ef84f16e8568edb6fdee4d127ed699cf4a8f8214037443c0371c3b9d23696fc6fdc9f393dec8cff7b7d7046fbbace2f6d247e7c1e8ae6594bfec075e02522427a8991f9055692e518d16eb50027f891582b4390b29b8ae753ad79ee37d6a0954958a00aed92fde15889f361d2b6b29262c05ac3a1eb0898761c9474d119b1a5a3702d35ae5146c8f93e2440f47d3d51acaf419c0620506616066d6ab25654e8eec32d245fb1f310e37986601b8f6b8c50220d681893444c624cd8bb04c4cb0d0eb826f80855e26d2145164edea790e82ddbd863163ee38ef4dca8c1ec994f81dfc970f457968fa348198acedd8ae001553ff2bf3e1ef27b8d5869e320d3800e3d952c39a84a2db161f973e690a5b055664bd3ddc215fa2b205ebd5e035a3ff8bb32982df11bb246d623905a9729653f01f6b24fb55110df16b57939edc83c9466d46977434ac93ef42426d8c2c48be52245d72deef6cb411ffeab5dc798ecf9ef964dfd80bdb25c9b489627501d86c179ac4eac77f5b78f7d09926175370b54079341a768747ce577c4a7e131fb218eeed49368dfd8f14ccbc84fbd717782826869b5b5d8b025248468bdb1640d4bba27fd64c7932084291d17cdaf3a75b669ecc20f9b4f246d33f42890d6e553fe5d05d882ca9334acdbb68bef7a95f3a66d40c54924d1a0bc7cada1e8afed2152ad02cb0a0682090e7306a93d388bcfc8cd158e1748731574d896af366dc6414a2f3c22673776ce5146ac031349f134db273178edffa46aefa691c818348f1e9318ac64b91ba7a8b3d1d306c1e80a009ae2abbaa8c06f1a7f14d156e1aac2dabf9090399a28f5770cb458119be24bc6d1719c4f483d85893ccb5aa99a4b18b5c012cc99905126fe65986038f9e173ded252bfabeaf829e0e3cfe6c5f9038e16f1afc2d12940f165135390dbe928a3efe5a59ad5e227cfae85cc4775f40b9b69c2f9b1c294a07305ddf77aa8a153f75e585ee54f60119f8b2f19feabebb1e2d5955ef18c0a85ca9f3039929d70f08839c0edb267df8909029d8a278a036217172bab6b11ae514475c2fb778e18a37253ad62ad6ec4cc34fa42a78ba7acfec7e4fd97719b5418b98c2dc8b727ed83d0af738a7272b4a04cbf077068abd6e537be0c09e406d6de0f723b777e1e5b350b8df7639bf0163042f487dd3a7339926a62108ef333b44bc21c7430bf51e6a3900de972a7a25c2d72f1b5c8e6ab27c2ebf63cffcfd7cda93132cb6ebe434fd79879296d371d394a70ac95bb48a021767e821859241bd6eabc24d8647f8f565c17b9a801d9679d00b2be1695bad03a539c5a7a197d295331df9399f64dc55e5a8706b18f7cf963026d1d61d653f5c716d5569cc87450607c11e0623c5de6ad6877db3f43e2d8f1c29b5f4f80550184db0680013e101916d325b7e8a435aba2e5f04419209802a1a1be9b7b6416737b4354222d81a40d704dc4409e34960e2870b089c694a7cdc7481f345ecbb2d3fb015cd180ffd3cdbc67a5e992355d2acdf05e6cc415abfd710370ab1465c955afa027ce880baa7b12378be822ea9358ea000cb08865de0d8eefc5f4e7c253cd87cfb279330c26c130229d050b2fdcf348e89e87b09b904e87abf579159677287bece0b50ea90f6f381a15817f98ac0c90719511b610d6bcc38f0a76c0f51dc14adea31c860cd48eff0b703f7cc44d21bf4ca8782f28b2682b3c1a4bd0778b8efa2045acedbb54787f5a4b46f450a92972cded99b2eded0d95b21834605469e464451f35b7234df05640dbcf1c47c1a56295b3c7752282e4dcba65e861be84c9257934b6160977d547c16f68db7edff1d81e0aa5ea4059c06811750165a672bff3248a75ad911aa85cc60a1e504d5858b8d662ae0f9d3d00f008e3251cefced444077f56c35fff25b3e5badde97cd15a4bc30969dfaf23428faf11f22716d27db3db5499496830a7238918a1e3bf53632b58d92d375fb9299cb1cf11363f4263f11a86a3411b4fb484e4daa5875aa19aa814ebe96a881a0c155515c678f4d73693f36d0ac88edf6c107fc53743ad90f4f951b0ced1b333c4a6975704602ed925e031abeb3a23457b21409298c24c8f8daa56851dae7ab182cf575c6152f587e913b4fa870d1f1cd6222c8c9336188e8520f3d35be3eb631884570ea97aa2646e4087022365dd7b78058321d56a773c3f946ff209d6ae74985839efd1928723b33b5a59f5a680c2604927a53f83b4ce899c7f30a09ee042b876efc3865aa433accb5687345b6eea9163e2558421779f6ad380c7248df406278b3ae793c497bd2428aad98b7d15");
    
}


- (void)test_createECCKeyToSignAndVerifyMessage{
    
    OSStatus status = noErr;
    (void)[KeychainWrapperMock deleteECCKeyPair_TEST];
    
    // init message to sign
    NSString *msg = @"hello world";
    NSData *digest = [Crypto sha256:[msg dataUsingEncoding:NSUTF8StringEncoding]];
    
    // create key pair
    status = [KeychainWrapperMock createRandomECCKey_TEST];
    XCTAssertEqual(status, errSecSuccess);
    
    // sign the digest
    NSData *signature_data = [KeychainWrapperMock createECCDigitalSignature_TEST:digest];
    
    // verify the signature
    BOOL valid_sig = [KeychainWrapperMock verifyECCDigitalSignature_TEST:digest signature:signature_data];
    XCTAssertTrue(valid_sig);
    
    // clean up - delete the key
    status = [KeychainWrapperMock deleteECCKeyPair_TEST];
    XCTAssertEqual(status, errSecSuccess);
}

@end
