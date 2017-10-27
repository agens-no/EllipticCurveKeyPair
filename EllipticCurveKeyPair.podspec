Pod::Spec.new do |s|
  s.name         = "EllipticCurveKeyPair"
  s.version      = "2.0"
  s.summary      = ""
  s.description  = <<-DESC
    Sign, verify, encrypt and decrypt using the Secure Enclave
  DESC
  s.homepage     = "https://github.com/agens-no/EllipticCurveKeyPair"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author             = { "Håvard Fossli" => "hfossli@gmail.com" }
  s.social_media_url   = ""
  s.ios.deployment_target = "8.0"
  s.osx.deployment_target = "10.9"
  s.watchos.deployment_target = "2.0"
  s.tvos.deployment_target = "9.0"
  s.source       = { :git => "https://github.com/agens-no/EllipticCurveKeyPair.git", :tag => s.version.to_s }
  s.source_files  = "Sources/**/*"
  s.frameworks  = ["Foundation", "LocalAuthentication", "Security"]
end
