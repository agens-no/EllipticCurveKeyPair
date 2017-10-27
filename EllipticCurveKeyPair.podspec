Pod::Spec.new do |s|
  s.name         = "EllipticCurveKeyPair"
  s.version      = "1.0"
  s.summary      = "Sign, verify, encrypt and decrypt using the Secure Enclave"
  s.description  = <<-DESC
    Sign, verify, encrypt and decrypt using the Secure Enclave
  DESC
  s.homepage     = "https://github.com/agens-no/EllipticCurveKeyPair"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author             = { "Håvard Fossli" => "hfossli@gmail.com" }
  s.social_media_url   = ""
  s.ios.deployment_target = "9.0"
  s.osx.deployment_target = "10.12"
  s.source       = { :git => "https://github.com/agens-no/EllipticCurveKeyPair.git", :tag => s.version.to_s }
  s.source_files  = "Sources/**/*"
  s.frameworks  = ["Foundation", "LocalAuthentication", "Security"]
end
