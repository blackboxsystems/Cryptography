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
    
    NSString *v = [NSString stringWithFormat:@"%i", APP_PROTOCOL_VERSION];
    NSString *km = [NSString stringWithFormat:@"%li", kdfMode];
    NSString *em = [NSString stringWithFormat:@"%li", encMode];
    NSString *r = [NSString stringWithFormat:@"%li", rounds];
    NSString *s = [DataFormatter hexDataToString:salt];
    NSString *blob = [DataFormatter hexDataToString:data];
    
    // TODO: convert to json
    NSMutableDictionary *pdict = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                  v, PROTOCOL_VERSION_STRING,
                                  km, PROTOCOL_KDF_MODE_STRING,
                                  em, PROTOCOL_ENCRYPTION_MODE_STRING,
                                  r, PROTOCOL_ROUNDS_STRING,
                                  s, PROTOCOL_SALT_STRING,
                                  blob, PROTOCOL_BLOB_STRING,
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


#pragma mark - PROTOCOL BACKUP DATA
+ (NSData * _Nullable)createBackupProtocolDataWithMode:(BBEncryptionMode)algo
                                        salt:(NSData *)salt
                                          iv:(NSData *)iv
                                      rounds:(NSInteger)rounds
                                      digest:(NSData *)digest{
    
    NSString *versionString = [NSString stringWithFormat:@"%i", APP_PROTOCOL_VERSION];
    NSString *modeString = [NSString stringWithFormat:@"%li", algo];
    NSString *roundString = [NSString stringWithFormat:@"%li", rounds];
    NSString *saltString = [DataFormatter hexDataToString:salt];
    NSString *ivString = [DataFormatter hexDataToString:iv];
    NSString *digestString = [DataFormatter hexDataToString:digest];
    
    NSMutableDictionary *pdict = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                  versionString, @"v",
                                  modeString, @"m",
                                  roundString, @"r",
                                  saltString, @"salt",
                                  ivString, @"iv",
                                  digestString, @"hmac",
                                  nil];
    
    NSString *json = [DataFormatter hexDataToString:[[self jsonStringWithPrettyPrint:(id)pdict pretty:YES] dataUsingEncoding:NSUTF8StringEncoding]];
    NSInteger jsonLength = json.length;
    NSString *total_json_bytes_hex = [[DataFormatter hexFromInt:jsonLength prefix:YES] substringFromIndex:2];
    NSString *total_bytes_json_hex_length = [NSString stringWithFormat:@"0%li",total_json_bytes_hex.length/2];

    NSData *protocol = [DataFormatter hexStringToData:[NSString stringWithFormat:@"%@%@%@",
                                                       total_bytes_json_hex_length,
                                                       total_json_bytes_hex,
                                                       json]];

    return protocol;
}



#pragma mark - PROTOCOL DATA FOR ONE-TIME-PROOF PAD
+ (NSData * _Nullable)createOTPProtocolData:(NSInteger)keyLength
                           rounds:(NSInteger)rounds
                             mode:(BBEncryptionMode)algo
                       difficulty:(NSInteger)diff
                             salt:(NSData *)salt{
    
    NSString *versionString = [NSString stringWithFormat:@"%i", APP_PROTOCOL_VERSION];
    NSString *modeString = [NSString stringWithFormat:@"%li", algo];
    NSString *roundString = [NSString stringWithFormat:@"%li", rounds];
    NSString *saltString = [DataFormatter hexDataToString:salt];
    NSString *diffString = [NSString stringWithFormat:@"%li", diff];
    
    //// JSON
    NSMutableDictionary *pdict = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                  versionString, @"v",
                                  modeString, @"m",
                                  roundString, @"r",
                                  diffString, @"diff",
                                  saltString, @"salt",
                                  nil];
    NSString *json = [DataFormatter hexDataToString:[[self jsonStringWithPrettyPrint:(id)pdict pretty:YES] dataUsingEncoding:NSUTF8StringEncoding]];
    NSInteger jsonLength = json.length;
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
    // corrupt/invalid data
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

//    NSLog(@"JSON reading:\ndata: %@\n\nobject: %@", json, jdict);
    return jdict;
}



@end
