#import <Foundation/Foundation.h>
#import "Crypto.h"

@interface Mnemonic : NSObject

// generate mnemonic from entropy
+ (NSString *)generateMemnonic:(NSData *)entropy;

// generate mnemonic with N words (12, 18, 24)
+ (NSString *)randomMemnonic:(NSInteger)Nwords;

// read seed_dictionary.txt and return data
+ (NSArray *)getDictionary;

+ (NSInteger)entropySize:(NSInteger)words;
+ (NSInteger)wordSize:(NSInteger)data;

@end
