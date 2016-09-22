//
//  CryptManager.h
//  CryptoTest
//
//  Created by Alexander on 9/19/16.
//

#import <Foundation/Foundation.h>

@interface CryptManager : NSObject;

+ (NSData *)encryptedDataForData:(NSData *)data
                        password:(NSString *)password
                          AESKey:(NSData **)AESKey
                              iv:(NSData **)iv
                            salt:(NSData **)salt
                           error:(NSError **)error;
+ (NSData *)randomDataOfLength:(size_t)length;
+ (NSData *)AESKeyForPassword:(NSString *)password
                         salt:(NSData *)salt;

@end

