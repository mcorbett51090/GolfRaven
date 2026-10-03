Pod::Spec.new do |s|
  s.name           = 'GolfravenAttest'
  s.version        = '0.0.0'
  s.summary        = 'GolfRaven device attestation: iOS App Attest and DeviceCheck.'
  s.description    = 'A thin, declarative wrapper over DCAppAttestService and DCDevice for the GolfRaven app. No hashing, no state, no retry: all of that is in the JS layer (src/attest).'
  s.author         = 'GolfRaven'
  s.homepage       = 'https://golfraven.invalid'
  s.license        = { :type => 'UNLICENSED' }
  s.platforms      = {
    :ios => '16.4'
  }
  s.swift_version  = '5.9'
  s.source         = { git: '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  s.source_files = "**/*.{h,m,swift}"
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule'
  }
end
