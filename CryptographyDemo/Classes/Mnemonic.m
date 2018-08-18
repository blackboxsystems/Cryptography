#import "Mnemonic.h"

@implementation Mnemonic : NSObject

NS_ENUM(NSInteger, CCSeedWords) {
    kSeedWords12 = 12,
    kSeedWords18 = 18,
    kSeedWords24 = 24
};

NS_ENUM(NSInteger, CCSeedEntropy) {
    kSeedBytes16 = 16,
    kSeedBytes24 = 24,
    kSeedBytes32 = 32
};

/*  -------------------------------------------------------------
 //  Mnemonic Generatation
 //  ------------------------------------------------------------
 */
+ (NSString *)generateMemnonic:(NSData *)entropy {
    
    if (entropy == nil || entropy.length % 8 != 0) {
        return nil;
    }
    
    NSInteger Nwords = [self wordSize:entropy.length];
    size_t nbytes = [self entropySize:Nwords];

    if (entropy.length != nbytes) {
        entropy = [Crypto generateRandomCrytoBytes:nbytes];
    }
    
    NSMutableData *bitmap = [[NSMutableData alloc] initWithData:entropy];
    
    // append checksum to the seed
    NSData *hash = [Crypto sha:entropy nbits:nbytes*8];
    NSData *checksum = [hash subdataWithRange:NSMakeRange(0, 2)];
    [bitmap appendData:checksum];
    
    NSString *bitmapString = [DataFormatter hexDataToString:bitmap];
    NSString *hex = [bitmapString substringToIndex:bitmapString.length-1];
    NSString *binary = [DataFormatter hexToBinary:hex];
    
    NSMutableArray *mapping = [[NSMutableArray alloc] initWithCapacity:Nwords];
    NSUInteger Nbits = binary.length/Nwords;
    for (NSInteger i = 0; i < Nwords; i++) {
        [mapping addObject:[binary substringToIndex:Nbits]];
        binary = [binary substringFromIndex:Nbits];
    }
    
    NSMutableArray *indexes = [[NSMutableArray alloc] init];
    for (NSInteger i = 0; i < Nwords; i++) {
        [indexes addObject:[NSString stringWithFormat:@"%i",[DataFormatter binaryStringToInt:mapping[i]]]];
    }
    
    NSArray *dictionary = [self getDictionary];
    NSMutableString *phrase = [[NSMutableString alloc] init];
    
    for (NSInteger i = 0; i < Nwords; i++) {
        NSString *word = [dictionary objectAtIndex:[[indexes objectAtIndex:i] integerValue]];
        [phrase appendString:[NSString stringWithFormat:@"%@ ",word]];
    }
    
    return [[phrase stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]
            stringByReplacingOccurrencesOfString:@"-" withString:@" "];
}

+ (NSString *)randomMemnonic:(NSInteger)Nwords {
    
    // calculate entropy
    size_t nbytes = [self entropySize:Nwords];
    NSData *entropy = [[Crypto generateRandomCrytoBytes:nbytes] subdataWithRange:NSMakeRange(0, nbytes)];
    
    return [self generateMemnonic:entropy];
}

+ (NSArray *)getDictionary {
    
    // get file data
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"seed_dictionary" ofType:@"txt"];
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    
    // integrity check on file
    NSData *fileHash = [Crypto sha256:data];
    assert([[DataFormatter hexDataToString:fileHash] isEqualToString:@"c1be978261f9acab4ab29806c57de07c7bea0a06acbc94f227d248da9b290c6b"]);
    
    // parse into word array
    NSString *dict = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSArray *wordArray = [dict componentsSeparatedByString:@"-"];
    
    return wordArray;
}

// get entropy size (in bytes) based on number of words for mnemonic
+ (NSInteger)entropySize:(NSInteger)words {
    switch (words) {
        case kSeedWords12:
            return kSeedBytes16;
        case kSeedWords18:
            return kSeedBytes24;
        case kSeedWords24:
            return kSeedBytes32;
        default:
            return kSeedBytes16;
    }
}

// get number of words in mnemonic based on entropy size (in bytes)
+ (NSInteger)wordSize:(NSInteger)nbytes {
    switch (nbytes) {
        case kSeedBytes16:
            return kSeedWords12;
        case kSeedBytes24:
            return kSeedWords18;
        case kSeedBytes32:
            return kSeedWords24;
        default:
            return kSeedWords12;
    }
}

@end
