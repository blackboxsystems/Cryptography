#import <XCTest/XCTest.h>
#import "Crypto.h"
#import "TestVectorConstants.h"

@interface AES_MerkleTree_Tests : XCTestCase

@end

@implementation AES_MerkleTree_Tests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)test_EncryptionThenMerkle
{
    // get merkle tree info for message data blocks
    NSString *msg = BLANK_PLAINTEXT_64;
    NSData *blankMessage = [DataFormatter hexStringToData:msg];
    NSInteger nleaves = [self numberOfLeaves:blankMessage];

    // set encryption key and iv
    NSData *iv = [DataFormatter hexStringToData:AES_IV_CTR];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_CTR256];
    
    // encrypt message
    NSData *encryptedData = [Crypto encryptAES_CTR:blankMessage
                                               key:key
                                                iv:iv];

    // generate merkle tree of encrypted data
    NSArray *merkleEncryptedTree = [self merkleTree:encryptedData];
    NSData *merkleEncryptedKey = [merkleEncryptedTree lastObject];
    
    // encrypt data again with the merkle root as key
    NSData *encryptedData2 = [Crypto encryptAES_CTR:encryptedData
                                                key:merkleEncryptedKey
                                                 iv:iv];
    
    // corrupt a portion (block/leaf) of the encrypted data, here we corrupt the first leaf
    NSInteger nthLeaf = 0;
    NSData *badLeaf = [Crypto generateRandomCrytoBytes:16];
    
    if (nthLeaf > nleaves) {
        nthLeaf = nleaves;
    }

    // set encrypted data and corrupt leafs
    NSMutableData *corruptEncryptedData = [[NSMutableData alloc] initWithData:encryptedData2];
    [corruptEncryptedData replaceBytesInRange:NSMakeRange(nthLeaf*16, 16) withBytes:badLeaf.bytes];
    
    // decrypt the corrupt data with merkle key
    NSData *decryptedCorruptData = [Crypto decryptAES_CTR:corruptEncryptedData
                                                      key:merkleEncryptedKey
                                                       iv:iv];

    // compute the merkle tree of decrypted layer
    NSArray *checkMerkleEncryptedTree = [self merkleTree:decryptedCorruptData];
    // get merkle root for first layer
    NSData *checkMerkleEncryptedKey = [checkMerkleEncryptedTree lastObject];
    
    NSLog(@"\n\ncheckMerkleEncryptedTree: %@\ncheckMerkleEncryptedKey: %@", checkMerkleEncryptedTree, [DataFormatter hexDataToString:checkMerkleEncryptedKey]);
    
    // check where data is corrupt
    NSInteger faultHeight = 0;
    NSMutableArray *corruptTrace = [[NSMutableArray alloc] init];
    
    // trace where the corruption occured in the encrypted layer from the merkle tree leaves
    if (![merkleEncryptedKey isEqualToData:checkMerkleEncryptedKey])
    {
        for (NSString *leaf in checkMerkleEncryptedTree)
        {
            faultHeight += 1;
            if (![merkleEncryptedTree containsObject:leaf]) {
                [corruptTrace addObject:[NSNumber numberWithInteger:faultHeight]];
            }
        }
    }
    
    NSLog(@"\n\ncorrupted leaf array: %@", corruptTrace);
}


- (NSInteger)numberOfLeaves:(NSData *)message
{
    NSArray *leaves = [self getMessageBlocks:message];
//    NSLog(@"\n\nmessage blocks[%li]: %@", leaves.count, leaves);
    return leaves.count;
}
- (NSArray *)merkleTree:(NSData *)message
{
    NSArray *leaves = [self getMessageBlocks:message];
    NSInteger nleaves = leaves.count;
//    NSLog(@"\n\nmessage blocks[%li]: %@", nleaves, leaves);
    
    NSMutableArray *tree = [[NSMutableArray alloc] init];
    NSData *merkleRoot = [Crypto sha256:leaves[0]];

    if (nleaves == 1)
    {
        nleaves = 2;
        [tree addObject:merkleRoot];
    }
    
    NSInteger nodes = leaves.count/2;
    
    for (NSInteger i = 0; i < leaves.count; i++)
    {
        merkleRoot = [Crypto sha256:leaves[i]];
        [tree addObject:merkleRoot];
    }
    
    if (nodes % 2 > 0)
    {
        [tree addObject:merkleRoot];
        [tree addObject:merkleRoot];
    }
//    NSLog(@"\n\nleaves[%li]: %@", tree.count, tree);

    for (NSInteger i = 0; i < tree.count-1; i++)
    {
        if (i % 2 == 0)
        {
            NSMutableData *concat = [[NSMutableData alloc] initWithData:tree[i]];
            [concat appendData:tree[i+1]];
            merkleRoot = [Crypto sha256:concat];
            [tree addObject:merkleRoot];
        }
    }
//    NSLog(@"\n\nmerkleRoot: %@\ntree: %@", [DataFormatter hexDataToString:merkleRoot], tree);

    return tree;
}

- (NSData *)merkleRoot:(NSData *)message
{
    NSArray *leaves = [self merkleTree:message];

    return [leaves lastObject];
}

- (NSArray *)getMessageBlocks:(NSData *)message
{
    NSInteger nbytes = message.length;
    NSInteger nblocks = floor(nbytes/kAES256_IV_LENGTH_BYTES);
    NSInteger pad = nbytes%kAES256_IV_LENGTH_BYTES;

    NSData *emptyBlock = [DataFormatter hexStringToData:BLANK_PLAINTEXT_16];
    
    NSMutableArray *mblocks = [[NSMutableArray alloc] init];
    for (NSInteger i = 0; i < nblocks; i++) {
        [mblocks addObject:[message subdataWithRange:NSMakeRange(i*16.0, 16.0)]];
    }
    
    if (pad > 0) {
        NSData *tempBlock = [Crypto xorDataLong:emptyBlock withData:[message subdataWithRange:NSMakeRange(message.length-pad, pad)]];
        [mblocks addObject:tempBlock];
    }
    
    return mblocks;
}


@end
