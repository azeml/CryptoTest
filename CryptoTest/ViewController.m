//
//  ViewController.m
//  CryptoTest
//
//  Created by Alexander on 9/19/16.
//

#import "ViewController.h"
#import "CryptManager.h"
#import "KeychainWrapper.h"

@interface ViewController ()

@property (nonatomic, weak) IBOutlet UITextView *textView;
@property (nonatomic, strong) KeychainWrapper *keychainWrapper;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.keychainWrapper = [KeychainWrapper new];
    [self useKeyAsync];
}

- (void)useKeyAsync {
    // Query private key object from the keychain.
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                            (__bridge id)kSecAttrLabel: @"my-se-key",
                            (__bridge id)kSecReturnRef: @YES,
                            (__bridge id)kSecUseOperationPrompt: @"Authenticate with Touch ID"
                            };
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Retrieve the key from the keychain.  No authentication is needed at this point.
        SecKeyRef privateKey;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);
        
        if (status == errSecSuccess) {
            // Sign the data in the digest/digestLength memory block.
            uint8_t signature[128];
            size_t signatureLength = sizeof(signature);
            uint8_t digestData[16];
            size_t digestLength = sizeof(digestData);
            status = SecKeyRawSign(privateKey, kSecPaddingPKCS1SHA1, digestData, digestLength, signature, &signatureLength);
            
            if (status == errSecSuccess) {
                [self printMessage:@"TouchID fingerprints have not changed sinse last launch"];
            } else if (status == -3) {
                [self deleteKeyAsync];
                [self generateKeyAsync];
                
                NSString *message = @"TouchID fingerprints have changed sinse last launch";
                [self printMessage:message];
                
                NSData *encryptedData = [self encryptMessage:message];
                
                [self sendData:encryptedData];
            } else {
                NSString *errorString = [self keychainErrorToString:status];
                NSString *message = [NSString stringWithFormat:@"Error: %@", errorString];
                [self printMessage:message];
            }
            
            CFRelease(privateKey);
        }
        else {
            //first launch
            [self generateKeyAsync];
        }
    });
}

- (void)sendData:(NSData *)data {
    NSURLSessionConfiguration *sessionConfiguration = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConfiguration];
    NSURL *url = [NSURL URLWithString:@"http://requestb.in/19v4zhn1"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPBody = data;
    request.HTTPMethod = @"POST";
    NSURLSessionDataTask *postDataTask = [session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSString *message = @"TouchID fingerprints have changed sinse last launch";
        if (error) {
            message = [message stringByAppendingFormat:@"\n%@", error.localizedDescription];
        } else {
            message = [message stringByAppendingFormat:@"\n%@", @"Message has been sent to server"];
        }
        [self printMessage:message];
    }];
    [postDataTask resume];
}

- (NSData *)encryptMessage:(NSString *)message {
    NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *passwordData =  [CryptManager randomDataOfLength:8];
    NSData *iv;
    NSData *salt;
    NSError *error;
    NSData *encryptedData = [CryptManager encryptedDataForData:messageData
                                                      password:passwordData.description
                                                            iv:&iv
                                                          salt:&salt
                                                         error:&error];

    [self.keychainWrapper mySetObject:passwordData.description forKey:(id)kSecValueData];

    return encryptedData;
}

- (void)generateKeyAsync {
    CFErrorRef error = NULL;
    SecAccessControlRef sacObject;
    
    //kSecAccessControlTouchIDCurrentSet
    //Touch ID from the set of currently enrolled fingers. Touch ID must be available and at least one finger must be enrolled. When fingers are added or removed, the item is invalidated.
    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                kSecAccessControlTouchIDCurrentSet | kSecAccessControlPrivateKeyUsage, &error);
    
    // Create parameters dictionary for key generation.
    NSDictionary *parameters = @{
                                 (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
                                 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
                                 (__bridge id)kSecAttrKeySizeInBits: @256,
                                 (__bridge id)kSecPrivateKeyAttrs: @{
                                         (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
                                         (__bridge id)kSecAttrIsPermanent: @YES,
                                         (__bridge id)kSecAttrLabel: @"my-se-key",
                                         },
                                 };
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Generate key pair.
        SecKeyRef publicKey, privateKey;
        OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
        NSString *errorString = [self keychainErrorToString:status];
        NSString *message = [NSString stringWithFormat:@"Key generation: %@", errorString];
        [self printMessage:message];
        
        if (status == errSecSuccess) {
            CFRelease(privateKey);
            CFRelease(publicKey);
        }
    });
    
}

- (void)deleteKeyAsync {
    NSDictionary *query = @{
                            (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                            (__bridge id)kSecAttrLabel: @"my-se-key",
                            (__bridge id)kSecReturnRef: @YES,
                            };
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        
        NSString *message = [NSString stringWithFormat:@"SecItemDelete status: %@", [self keychainErrorToString:status]];
        
        [self printMessage:message];
    });
}

- (NSString *)keychainErrorToString:(OSStatus)error {
    NSString *message = [NSString stringWithFormat:@"%ld", (long)error];
    
    switch (error) {
        case errSecSuccess:
            message = @"success";
            break;
            
        case errSecDuplicateItem:
            message = @"error item already exists";
            break;
            
        case errSecItemNotFound :
            message = @"error item not found";
            break;
            
        case errSecAuthFailed:
            message = @"error item authentication failed";
            break;
            
        default:
            break;
    }
    
    return message;
}

- (void)printMessage:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        // Update the result in the main queue because we may be calling from a background queue.
        self.textView.text = message;
    });
}
@end
