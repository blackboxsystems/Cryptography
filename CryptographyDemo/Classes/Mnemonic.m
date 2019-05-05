#import "Mnemonic.h"

@implementation Mnemonic : NSObject

NS_ENUM(NSInteger, CCSeedWords) {
    kSeedWords12 = 12,
    kSeedWords18 = 18,
    kSeedWords24 = 24,
    kSeedWords48 = 48
};

NS_ENUM(NSInteger, CCSeedEntropy) {
    kSeedBytes16 = 16,
    kSeedBytes24 = 24,
    kSeedBytes32 = 32,
    kSeedBytes64 = 64
};


#pragma mark - GENERATE MNEMONIC FROM ENTROPY
+ (NSString *)generateMemnonic:(NSData *)entropy {
    
    if (entropy == nil) {
        return nil;
    }
    
    NSInteger Nwords = [self wordSize:entropy.length];
    size_t nbytes = [self entropySize:Nwords];
    
    if (entropy.length != nbytes) {
        entropy = [entropy subdataWithRange:NSMakeRange(0, (nbytes > entropy.length ? entropy.length : nbytes))];
    }
    
    NSMutableData *bitmap = [[NSMutableData alloc] initWithData:entropy];
    NSData *hash = [Crypto sha256:entropy];
    NSData *checksum = [hash subdataWithRange:NSMakeRange(0, 2)];
    [bitmap appendData:checksum];
    
    NSString *bitmapString = [DataFormatter hexDataToString:bitmap];
    NSString *hex = [bitmapString substringToIndex:bitmapString.length-1];
    NSString *binary = [DataFormatter hexToBinary:hex];
    
    NSMutableArray *mapping = [[NSMutableArray alloc] initWithCapacity:Nwords];
    NSString *bitmask = @"11111111111";
    for (NSInteger i = 0; i < Nwords; i++) {
        if (binary.length < 11) {
            [mapping addObject:[NSString stringWithFormat:@"%@%@", binary, [bitmask substringToIndex:11-binary.length]]];
            break;
        }
        [mapping addObject:[binary substringToIndex:11]];
        binary = [binary substringFromIndex:11];
    }
    
    NSMutableArray *indexes = [[NSMutableArray alloc] init];
    for (NSInteger i = 0; i < Nwords; i++) {
        [indexes addObject:[NSString stringWithFormat:@"%i",[DataFormatter binaryStringToInt:mapping[i]]]];
    }
    
    NSArray *dictionary = [self getBIP32Dictionary];
    NSMutableString *phrase = [[NSMutableString alloc] init];
    
    for (NSInteger i = 0; i < Nwords; i++) {
        NSInteger wordIndex = [[indexes objectAtIndex:i] integerValue];
        NSString *word = [dictionary objectAtIndex:wordIndex];
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

+ (NSData *)entropyFromMemnonic:(NSString *)mnemonic {
    
    if (mnemonic == nil) {
        return nil;
    }
    
    NSArray *words;
    if ([mnemonic componentsSeparatedByString:@" "].count > 0) {
        words = [mnemonic componentsSeparatedByString:@" "];
    } else if ([mnemonic componentsSeparatedByString:@"-"].count > 0) {
        words = [mnemonic componentsSeparatedByString:@"-"];
    } else if ([mnemonic componentsSeparatedByString:@"."].count > 0) {
        words = [mnemonic componentsSeparatedByString:@"."];
    } else if ([mnemonic componentsSeparatedByString:@","].count > 0) {
        words = [mnemonic componentsSeparatedByString:@","];
    }
    
    NSInteger nwords = words.count;
    if (nwords != kSeedWords12 && nwords != kSeedWords18 && nwords != kSeedWords24 && nwords != kSeedWords48) {
        return nil;
    }
    
    NSArray *dictionary = [self getBIP32Dictionary];
    
    NSMutableArray *wordIndexes = [[NSMutableArray alloc] initWithCapacity:nwords];
    NSInteger index = 0;
    for (NSInteger i = 0; i < nwords; i++)
    {
        index = 0;
        for (NSString *word in dictionary)
        {
            if ([word isEqualToString:words[i]]) {
                [wordIndexes addObject:[NSString stringWithFormat:@"%li",(NSInteger)index]];
            }
            index++;
        }
    }
    
    NSMutableString *binaries = [[NSMutableString alloc] init];
    for (NSInteger i = 0; i < nwords; i++)
    {
        NSString *str = [DataFormatter hexToBinary:[DataFormatter hexFromInt:[wordIndexes[i] integerValue] prefix:YES]];
        if (str.length > 11) {
            str = [str substringFromIndex:str.length-11];
        }
        [binaries appendString:str];
    }
    
    if (!binaries) {
        return nil;
    }
    
    NSString *entropy = [DataFormatter binaryToHex:binaries];
    NSData *entropy_data = [DataFormatter hexStringToData:entropy];
    NSData *checksum = nil;
    NSInteger nbytes = kSeedBytes32;
    
    if (binaries.length == 132) {
        nbytes = kSeedBytes16;
    } else if (binaries.length == 198) {
        nbytes = kSeedBytes24;
    } else if (binaries.length == 264) {
        nbytes = kSeedBytes32;
    } else {
        nbytes = kSeedBytes64;
    }
    
    entropy_data = [entropy_data subdataWithRange:NSMakeRange(0, nbytes)];
    checksum = [[Crypto sha256:entropy_data] subdataWithRange:NSMakeRange(0, 2)];
    
    NSData *hash = [Crypto sha256:entropy_data];
    NSData *checksum_hash = [hash subdataWithRange:NSMakeRange(0, 2)];
    
    if ([checksum_hash isEqualToData:checksum]) {
        return entropy_data;
    }
    
    return nil;
}

+ (NSArray *)getBIP32Dictionary{
    
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
        case kSeedWords48:
            return kSeedBytes64;
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
        case kSeedBytes64:
            return kSeedWords48;
        default:
            return kSeedWords12;
    }
}

@end
