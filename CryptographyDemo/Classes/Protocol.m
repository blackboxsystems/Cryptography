#import "Protocol.h"
#import "Crypto.h"

/* Protocol Format: opcode/protocol packet with serialized json object. */

@implementation Protocol


+ (NSString * _Nullable)jsonStringWithPrettyPrint:(id)object pretty:(BOOL)prettyPrint{

    if (![NSJSONSerialization isValidJSONObject:object]){
        return nil;
    }
    
    NSError *error = nil;
    NSJSONWritingOptions options = (NSJSONWritingOptions)(prettyPrint ? NSJSONWritingPrettyPrinted : 0);
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:object
                                                       options:options
                                                         error:&error];
    
    if (! jsonData) {
        NSLog(@"%s: error: %@", __func__, error.localizedDescription);
        return @"{}";
    } else {
        return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
}


#pragma mark - PROTOCOL DATA FOR AUTH KEY
+ (NSData *)createProtocolWithBlob:(NSData *)data
                           kdfMode:(BBKDFMode)kdfMode
                           encMode:(BBEncryptionMode)encMode
                              salt:(NSData *)salt
                            rounds:(NSInteger)rounds{
    
    NSString *versionString = [NSString stringWithFormat:@"%i", APP_PROTOCOL_VERSION];
    NSString *encmodeString = [NSString stringWithFormat:@"%li", encMode];
    NSString *kdfmodeString = [NSString stringWithFormat:@"%li", kdfMode];
    NSString *roundString = [NSString stringWithFormat:@"%li", rounds];
    NSString *saltString = [DataFormatter hexDataToString:salt];
    NSString *blob = [DataFormatter hexDataToString:data];
    
    NSMutableDictionary *pdict = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                  versionString, PROTOCOL_VERSION_KEY,
                                  kdfmodeString, PROTOCOL_KDF_MODE_KEY,
                                  encmodeString, PROTOCOL_ENCRYPTION_MODE_KEY,
                                  roundString, PROTOCOL_ROUNDS_KEY,
                                  saltString, PROTOCOL_SALT_KEY,
                                  blob, PROTOCOL_BLOB_KEY,
                                  nil];
    
    NSString *json = [DataFormatter hexDataToString:[[self jsonStringWithPrettyPrint:(id)pdict pretty:NO] dataUsingEncoding:NSUTF8StringEncoding]];
    NSInteger jsonLength = [DataFormatter hexStringToData:json].length;
    NSString *total_json_bytes_hex = [[DataFormatter hexFromInt:jsonLength prefix:YES] substringFromIndex:2];
    NSString *total_bytes_json_hex_length = [NSString stringWithFormat:@"0%li",total_json_bytes_hex.length/2];
    
    NSData *protocol = [DataFormatter hexStringToData:[NSString stringWithFormat:@"%@%@%@",
                                                       total_bytes_json_hex_length,
                                                       total_json_bytes_hex,
                                                       json]];
    return protocol;
}


#pragma mark - PROTOCOL DATA FOR ONE-TIME-PROOF PAD
+ (NSData *)createOTPProtocolData:(NSData *)data
                             salt:(NSData *)salt
                           rounds:(NSInteger)rounds
                      blockRounds:(NSInteger)blockRounds
                          kdfmode:(BBKDFMode)kdfMode
                          encmode:(BBEncryptionMode)encMode
                       difficulty:(NSInteger)difficulty{
    
    NSString *versionString = [NSString stringWithFormat:@"%i", APP_PROTOCOL_VERSION];
    NSString *encmodeString = [NSString stringWithFormat:@"%li", encMode];
    NSString *kdfmodeString = [NSString stringWithFormat:@"%li", kdfMode];
    NSString *roundsString = [NSString stringWithFormat:@"%li", rounds];
    NSString *blockRoundsString = [NSString stringWithFormat:@"%li", blockRounds];
    NSString *saltString = [DataFormatter hexDataToString:salt];
    NSString *diffString = [NSString stringWithFormat:@"%li", difficulty];
    NSString *blobString = [DataFormatter hexDataToString:data];
    
    NSMutableDictionary *pdict = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                  versionString, PROTOCOL_VERSION_KEY,
                                  kdfmodeString, PROTOCOL_KDF_MODE_KEY,
                                  encmodeString, PROTOCOL_ENCRYPTION_MODE_KEY,
                                  roundsString, PROTOCOL_ROUNDS_KEY,
                                  blockRoundsString, PROTOCOL_BLOCK_ROUNDS_KEY,
                                  diffString, PROTOCOL_DIFFICULTY_KEY,
                                  saltString, PROTOCOL_SALT_KEY,
                                  blobString, PROTOCOL_BLOB_KEY,
                                  nil];
    
    NSString *json = [DataFormatter hexDataToString:[[self jsonStringWithPrettyPrint:(id)pdict pretty:NO] dataUsingEncoding:NSUTF8StringEncoding]];
    NSInteger jsonLength = [DataFormatter hexStringToData:json].length;
    NSString *total_json_bytes_hex = [[DataFormatter hexFromInt:jsonLength prefix:YES] substringFromIndex:2];
    NSString *total_bytes_json_hex_length = [NSString stringWithFormat:@"0%li",total_json_bytes_hex.length/2];
    
    NSData *protocol = [DataFormatter hexStringToData:[NSString stringWithFormat:@"%@%@%@",
                                                       total_bytes_json_hex_length,
                                                       total_json_bytes_hex,
                                                       json]];
    return protocol;
}


#pragma mark - PARSING PROTOCOL DATA FOR AUTH KEY
+ (NSDictionary * _Nullable)parseBlob:(NSData *)data {
    return [self protocolParser:data];
}


+ (NSDictionary * _Nullable)protocolParser:(NSData *)data {
    
    if (data == nil || data.length == 0) {
        return nil;
    }
    
    NSInteger index = 0;
    NSData *protocolLengthBytes = [data subdataWithRange:NSMakeRange(index, 1)];
    index++;
    NSInteger protocolLength = [DataFormatter hexDataToInt:protocolLengthBytes];
    
    if (protocolLength > 2) {
        return nil;
    }

    NSInteger protocolBytesLength = [DataFormatter hexDataToInt:[data subdataWithRange:NSMakeRange(index, protocolLength)]];
    index += protocolLength;
    
    if (index + protocolBytesLength > data.length) {
        return nil;
    }
    
    NSError *error;
    NSData *json = [data subdataWithRange:NSMakeRange(index, protocolBytesLength)];
    NSDictionary *jdict = [NSJSONSerialization JSONObjectWithData:json
                                                          options:NSJSONReadingMutableContainers
                                                            error:&error];

    return jdict;
}



@end
