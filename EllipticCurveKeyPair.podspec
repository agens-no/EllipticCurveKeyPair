Pod::Spec.new do |s|
  s.name         = "EllipticCurveKeyPair"
  s.version      = "1.0.2"
  s.summary      = "Sign, verify, encrypt and decrypt using the Secure Enclave"
  s.description  = <<-DESC
    Create and manage an Elliptic Curve Key Pair on the Secure Enclave on iOS or MacOS.
  DESC
  s.homepage     = "https://github.com/agens-no/EllipticCurveKeyPair"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author       = {
    "Håvard Fossli" => "hfossli@gmail.com",
    "Marcin Krzyżanowski" => "marcin.krzyzanowski@gmail.com"
  }
  s.ios.deployment_target = "9.0"
  s.osx.deployment_target = "10.12.1"
  s.source       = { :git => "https://github.com/agens-no/EllipticCurveKeyPair.git", :tag => s.version.to_s }
  s.source_files  = "Sources/**/*"
  s.frameworks  = ["Foundation", "LocalAuthentication", "Security"]
end
