//
//  ViewController.m
//  CryptoTest
//
//  Created by Alexander on 9/19/16.
//

#import "ViewController.h"
#import "CryptManager.h"
#import "KeychainWrapper.h"

static const UInt8 publicKeyIdentifier[] = "com.apple.sample.publickey";
static const UInt8 privateKeyIdentifier[] = "com.apple.sample.privatekey";
const size_t CIPHER_BUFFER_SIZE = 256;
const size_t BUFFER_SIZE = 128;
const uint32_t PADDING = kSecPaddingPKCS1;

@interface ViewController () {
    SecKeyRef publicKeyRSA;
    SecKeyRef privateKeyRSA;
    NSData *publicTag;
    NSData *privateTag;
}

@property (nonatomic, weak) IBOutlet UITextView *textView;
@property (nonatomic, strong) KeychainWrapper *keychainWrapper;
@property (nonatomic, strong) NSData *AESKey;

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
                NSString *message = @"TouchID fingerprints have changed sinse last launch";
                [self printMessage:message];
                
                NSData *encryptedData = [self encryptMessage:message];
                
                [self generateKeyPair:2048];
                
                //tmp
                self.AESKey = [@"12345678" dataUsingEncoding:NSUTF8StringEncoding];
                
                [self encryptAESKey];
                
                [self sendData:encryptedData];

                [self deleteKeyAsync];
                [self generateKeyAsync];
                
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

- (void)encryptAESKey {
    uint8_t *plainBuffer = (uint8_t *)self.AESKey.bytes;
    uint8_t *cipherBuffer = (uint8_t *)calloc(CIPHER_BUFFER_SIZE, sizeof(uint8_t));
    
    NSLog(@"init() plainBuffer: %s", plainBuffer);
    //NSLog(@"init(): sizeof(plainBuffer): %d", sizeof(plainBuffer));
    [self encryptWithPublicKey:(UInt8 *)plainBuffer cipherBuffer:cipherBuffer];
    
    memset(plainBuffer, 0, self.AESKey.length);
    
    [self decryptWithPrivateKey:(UInt8 *)cipherBuffer plainBuffer:plainBuffer];
    
}

- (void)encryptWithPublicKey:(uint8_t *)plainBuffer cipherBuffer:(uint8_t *)cipherBuffer
{
    OSStatus status = noErr;
    size_t plainBufferSize = BUFFER_SIZE;
    size_t cipherBufferSize = CIPHER_BUFFER_SIZE;
    
    NSLog(@"SecKeyGetBlockSize() public = %lu", SecKeyGetBlockSize(publicKeyRSA));
    //  Error handling
    // Encrypt using the public.
    status = SecKeyEncrypt(publicKeyRSA,
                           PADDING,
                           plainBuffer,
                           plainBufferSize,
                           &cipherBuffer[0],
                           &cipherBufferSize
                           );
    NSLog(@"encryption result code: %d (size: %lu)", (int)status, cipherBufferSize);
    NSLog(@"encrypted text: %s", cipherBuffer);
}

- (void)decryptWithPrivateKey:(uint8_t *)cipherBuffer plainBuffer:(uint8_t *)plainBuffer
{
    OSStatus status = noErr;
    
    size_t cipherBufferSize = CIPHER_BUFFER_SIZE;
    
    NSLog(@"decryptWithPrivateKey: length of buffer: %lu", BUFFER_SIZE);
    NSLog(@"decryptWithPrivateKey: length of input: %lu", cipherBufferSize);
    NSLog(@"SecKeyGetBlockSize() private = %lu", SecKeyGetBlockSize(privateKeyRSA ));
    
    // DECRYPTION
    size_t plainBufferSize = BUFFER_SIZE;
    
    //  Error handling
    status = SecKeyDecrypt(privateKeyRSA,
                           PADDING,
                           &cipherBuffer[0],
                           cipherBufferSize,
                           &plainBuffer[0],
                           &plainBufferSize
                           );
    NSLog(@"decryption result code: %d (size: %lu)", (int)status, plainBufferSize);
    NSLog(@"FINAL decrypted text: %s", plainBuffer);
    
}

- (void)generateKeyPair:(NSUInteger)keySize {
    OSStatus sanityCheck = noErr;
    publicKeyRSA = NULL;
    privateKeyRSA = NULL;
    privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
    publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
    
    //  LOGGING_FACILITY1( keySize == 512 || keySize == 1024 || keySize == 2048, @"%d is an invalid and unsupported key size.", keySize );
    
    // First delete current keys.
    //  [self deleteAsymmetricKeys];
    
    // Container dictionaries.
    NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
    
    // Set top level dictionary for the keypair.
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    // Set the private key dictionary.
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set the public key dictionary.
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set attributes to top level dictionary.
    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
    sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKeyRSA, &privateKeyRSA);
    //  LOGGING_FACILITY( sanityCheck == noErr && publicKey != NULL && privateKey != NULL, @"Something really bad went wrong with generating the key pair." );
    if(sanityCheck == noErr  && publicKeyRSA != NULL && privateKeyRSA != NULL)
    {
        NSLog(@"Successful");
    }
    //  [privateKeyAttr release];
    //  [publicKeyAttr release];
    //  [keyPairAttr release];
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
    NSData *key;
    NSData *iv;
    NSData *salt;
    NSError *error;
    NSData *encryptedData = [CryptManager encryptedDataForData:messageData
                                                      password:passwordData.description
                                                        AESKey:&key
                                                            iv:&iv
                                                          salt:&salt
                                                         error:&error];
    self.AESKey = key;
    
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
