import Foundation
import Darwin

@_silgen_name("reflection_main")
func reflectionMain(_ argc: Int32, _ argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32

struct Payload { var value: Int; var label: String }
class Box<T> { var value: T; init(_ value: T) { self.value = value } }
enum Choice<T> { case empty; case value(T) }
let types: [Any.Type] = [Payload.self, Box<Payload>.self, Optional<Box<Payload>>.self,
                         (Int, String).self, ((Int) -> String).self, Choice<Payload>.self]
let addresses = types.map { String(unsafeBitCast($0, to: UInt.self), radix: 16) }.joined(separator: "\n") + "\n"
var fds: [Int32] = [0, 0]
precondition(pipe(&fds) == 0)
addresses.withCString { ptr in precondition(write(fds[1], ptr, strlen(ptr)) == strlen(ptr)) }
close(fds[1]); precondition(dup2(fds[0], STDIN_FILENO) >= 0); close(fds[0])
let args = [strdup("swift-reflection-test"), strdup(String(getpid())), nil]
var argv = args
let rc = argv.withUnsafeMutableBufferPointer { reflectionMain(2, $0.baseAddress!) }
args.forEach { free($0) }
exit(rc)
