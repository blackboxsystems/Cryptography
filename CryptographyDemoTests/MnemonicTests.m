#import <XCTest/XCTest.h>
#import "Mnemonic.h"
#import "DataFormatter.h"


@interface MnemonicTests : XCTestCase

@end

@implementation MnemonicTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}


#pragma mark - BIP32 DICTIONARY REFERENCE
- (void)test_BIP32_Dictionary_Integrity{
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"seed_dictionary" ofType:@"txt"];
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    XCTAssertTrue([[DataFormatter hexDataToString:[Crypto sha256:data]] isEqualToString:@"c1be978261f9acab4ab29806c57de07c7bea0a06acbc94f227d248da9b290c6b"]);
}

- (void)test_Mnemonic_Blank12 {
    NSData *entropy = [DataFormatter hexStringToData:@"00000000000000000000000000000000"];
    NSString *mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
}


- (void)test_Mnemonic_Blank18 {
    NSData *entropy = [DataFormatter hexStringToData:@"000000000000000000000000000000000000000000000000"];
    NSString *mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent");
}


- (void)test_Mnemonic_Blank24 {
    NSData *entropy = [DataFormatter hexStringToData:@"0000000000000000000000000000000000000000000000000000000000000000"];
    NSString *mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art");
}


- (void)test_Mnemonic_Max12 {
    NSData *entropy = [DataFormatter hexStringToData:@"ffffffffffffffffffffffffffffffff"];
    NSString *mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
}


- (void)test_Mnemonic_Max18 {
    NSData *entropy = [DataFormatter hexStringToData:@"ffffffffffffffffffffffffffffffffffffffffffffffff"];
    NSString *mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when");
}


- (void)test_Mnemonic_Max24 {
    NSData *entropy = [DataFormatter hexStringToData:@"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"];
    NSString *mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote");
}


- (void)test_Mnemonic_12_Words {
    NSData *entropy = [DataFormatter hexStringToData:@"f30f8c1da665478f49b001d94c5fc452"];
    NSString *mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"vessel ladder alter error federal sibling chat ability sun glass valve picture");
}


- (void)test_Mnemonic_18_Words {
    NSData *entropy = [DataFormatter hexStringToData:@"6610b25967cdcca9d59875f5cb50b0ea75433311869e930b"];
    NSString *mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog");
}


- (void)test_Mnemonic_24_Words {
    NSData *entropy = [DataFormatter hexStringToData:@"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c"];
    NSString *mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length");
}


- (void)test_Mnemonic_7f {
    NSData *entropy = [DataFormatter hexStringToData:@"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"];
    NSString *mnemonic = [Mnemonic generateMemnonic:entropy];
    XCTAssertEqualObjects(mnemonic, @"legal winner thank year wave sausage worth useful legal winner thank yellow");
}

- (void)test_mnemonicToEntropy {
    NSData *entropy = [Mnemonic entropyFromMemnonic:@"legal winner thank year wave sausage worth useful legal winner thank yellow"];
    XCTAssertEqualObjects([DataFormatter hexDataToString:entropy], @"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
    
    entropy = [Mnemonic entropyFromMemnonic:@"hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"];
    XCTAssertEqualObjects([DataFormatter hexDataToString:entropy], @"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c");
}


@end
