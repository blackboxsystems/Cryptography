#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface OTPCrypto : NSObject

+ (NSData *)deriveOTP:(NSString *)seed
                 salt:(NSData *)salt
                 data:(NSData *)plaintext
               rounds:(NSInteger)rounds
           difficulty:(NSInteger)diff
              encrypt:(BOOL)encrypting;

+ (NSData *)deriveTimedOTP:(NSString *)seed
                      salt:(NSData *)salt
                      data:(NSData *)plaintext
                   padTime:(double)padTime
                    rounds:(NSInteger)rounds
               blockRounds:(NSInteger)blockRounds
                   encrypt:(BOOL)encrypt;
@end

NS_ASSUME_NONNULL_END
