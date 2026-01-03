//
//  AnomalyPythonScorer.m
//  SniffNetBar
//
//  Executes a local Python scoring script
//

#import "AnomalyPythonScorer.h"

@interface SNBAnomalyPythonScorer ()
@property (nonatomic, copy) NSString *scriptPath;
@property (nonatomic, copy) NSString *modelPath;
@end

@implementation SNBAnomalyPythonScorer

- (instancetype)initWithScriptPath:(NSString *)scriptPath
                         modelPath:(NSString *)modelPath {
    self = [super init];
    if (self) {
        _scriptPath = [scriptPath copy] ?: @"";
        _modelPath = [modelPath copy] ?: @"";
    }
    return self;
}

- (NSNumber *)scoreFeaturePayload:(NSDictionary<NSString *, NSNumber *> *)payload
                            error:(NSError **)error {
    if (self.scriptPath.length == 0 || self.modelPath.length == 0) {
        return nil;
    }
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:self.scriptPath] || ![fm fileExistsAtPath:self.modelPath]) {
        return nil;
    }

    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/bin/python3";
    task.arguments = @[self.scriptPath, self.modelPath];

    NSPipe *stdinPipe = [NSPipe pipe];
    NSPipe *stdoutPipe = [NSPipe pipe];
    task.standardInput = stdinPipe;
    task.standardOutput = stdoutPipe;

    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:payload options:0 error:error];
    if (!jsonData) {
        return nil;
    }

    @try {
        [task launch];
    } @catch (NSException *exception) {
        return nil;
    }

    [[stdinPipe fileHandleForWriting] writeData:jsonData];
    [[stdinPipe fileHandleForWriting] closeFile];

    [task waitUntilExit];
    NSData *outData = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];

    if (task.terminationStatus != 0 || outData.length == 0) {
        return nil;
    }

    NSDictionary *result = [NSJSONSerialization JSONObjectWithData:outData options:0 error:error];
    if (![result isKindOfClass:[NSDictionary class]]) {
        return nil;
    }
    NSNumber *score = result[@"score"];
    if (![score isKindOfClass:[NSNumber class]]) {
        return nil;
    }
    return score;
}

@end
