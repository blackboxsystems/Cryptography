//
//  Mnemonic.h
//  CryptographyDemo
//
//  Created by Hello World on 5/15/18.
//  Copyright © 2018 blackboxsystems. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Crypto.h"

@interface Mnemonic : NSObject

// generate mnemonic from entropy
+ (NSString *)generateMemnonic:(NSData *)entropy;

// generate mnemonic with N words (12, 18, 24)
+ (NSString *)randomMemnonic:(NSInteger)Nwords;

// read seed_dictionary.txt and return data
+ (NSArray *)getDictionary;

@end
