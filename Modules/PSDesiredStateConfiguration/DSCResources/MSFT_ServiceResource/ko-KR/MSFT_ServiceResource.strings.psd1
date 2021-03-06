# Localized	12/07/2019 11:51 AM (GMT)	303:6.40.20520 	MSFT_ServiceResource.strings.psd1
# Localized resources for MSFT_UserResource

ConvertFrom-StringData @'
###PSLOC
ServiceNotFound='{0}' 서비스를 찾을 수 없습니다.
CannotStartAndDisable=서비스를 시작하고 사용하지 않도록 설정할 수 없습니다.
CannotStopServiceSetToStartAutomatically=서비스를 중지하고 자동으로 시작하도록 설정할 수 없습니다.
ServiceAlreadyStarted='{0}' 서비스가 이미 시작되었습니다. 작업이 필요하지 않습니다.
ServiceStarted='{0}' 서비스가 시작되었습니다.
ServiceStopped='{0}' 서비스가 중지되었습니다.
ErrorStartingService='{0}' 서비스를 시작하지 못했습니다. 서비스에 대해 제공된 '{1}' 경로를 확인하십시오. 메시지: '{2}'
OnlyOneParameterCanBeSpecified=다음 매개 변수 중 하나만 지정할 수 있습니다. '{0}', '{1}'.
StartServiceWhatIf=서비스 시작
ServiceAlreadyStopped='{0}' 서비스가 이미 중지되었습니다. 작업이 필요하지 않습니다.
ErrorStoppingService='{0}' 서비스를 중지하지 못했습니다. 메시지: '{1}'
ErrorRetrievingServiceInformation='{0}' 서비스에 대한 정보를 검색하지 못했습니다. 메시지: '{1}'
ErrorSettingServiceCredential='{0}' 서비스에 대한 자격 증명을 설정하지 못했습니다. 메시지: '{1}'
SetCredentialWhatIf=자격 증명 설정
SetStartupTypeWhatIf=시작 유형 설정
ErrorSettingServiceStartupType='{0}' 서비스에 대한 시작 유형을 설정하지 못했습니다. 메시지: '{1}'
TestUserNameMismatch='{0}' 서비스의 사용자 이름은 '{1}'입니다. '{2}'과(와) 일치하지 않습니다.
TestStartupTypeMismatch='{0}' 서비스의 시작 유형은 '{1}'입니다. '{2}'과(와) 일치하지 않습니다.
MethodFailed='{1}'의 '{0}' 메서드가 실패했습니다. 오류 코드: '{2}'.
ErrorChangingProperty='{0}' 속성을 변경하지 못했습니다. 메시지: '{1}'
ErrorSetingLogOnAsServiceRightsForUser=서비스로 로그온할 권한을 '{0}'에 부여하는 동안 오류가 발생했습니다. 메시지: '{1}'.
CannotOpenPolicyErrorMessage=정책 관리자를 열 수 없습니다.
UserNameTooLongErrorMessage=사용자 이름이 너무 깁니다.
CannotLookupNamesErrorMessage=사용자 이름을 조회하지 못했습니다.
CannotOpenAccountErrorMessage=사용자에 대한 정책을 열지 못했습니다.
CannotCreateAccountAccessErrorMessage=사용자에 대한 정책을 만들지 못했습니다.
CannotGetAccountAccessErrorMessage=사용자 정책 권한을 가져오지 못했습니다.
CannotSetAccountAccessErrorMessage=사용자 정책 권한을 설정하지 못했습니다.
BinaryPathNotSpecified=새 서비스를 만들려고 할 때 실행 파일에 대한 경로 지정
ServiceAlreadyExists=만들려는 '{0}' 서비스가 이미 존재함
ServiceExistsSamePath=만들려는 '{0}' 서비스가 '{1}' 경로와 함께 이미 존재함
ServiceNotExists='{0}' 서비스가 존재하지 않습니다. 새 서비스를 만들려면 실행 파일에 대한 경로를 지정하십시오.
ErrorDeletingService='{0}' 서비스를 삭제하는 중 오류 발생
ServiceDeletedSuccessfully='{0}' 서비스 삭제 완료
TryDeleteAgain=서비스가 삭제될 때까지 2초 동안 기다리십시오.
WritePropertiesIgnored='{0}' 서비스가 이미 존재합니다. 기존 서비스에 대해 Status, DisplayName, Description, Dependencies 등의 쓰기 속성이 무시됩니다.
###PSLOC

'@

