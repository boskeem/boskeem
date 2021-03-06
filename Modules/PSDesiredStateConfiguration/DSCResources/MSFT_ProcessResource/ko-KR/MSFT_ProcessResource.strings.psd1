# Localized	12/07/2019 11:50 AM (GMT)	303:6.40.20520 	MSFT_ProcessResource.strings.psd1
# Localized resources for MSFT_UserResource

ConvertFrom-StringData @'
###PSLOC
FileNotFound=환경 경로에서 파일을 찾을 수 없습니다.
AbsolutePathOrFileName=절대 경로 또는 파일 이름이 필요합니다.
InvalidArgument=값이 '{1}'인 '{0}' 인수가 잘못되었습니다.
InvalidArgumentAndMessage={0} {1}
ProcessStarted=프로세스 일치 경로 '{0}'이(가) 시작되었습니다.
ProcessesStopped=ID가 '({1})'인 프로세스 일치 경로 '{0}'이(가) 중지되었습니다.
ProcessAlreadyStarted=실행 중인 프로세스 일치 경로 '{0}'이(가) 있습니다. 작업이 필요하지 않습니다.
ProcessAlreadyStopped=실행 중인 프로세스 일치 경로 '{0}'이(가) 없습니다. 작업이 필요하지 않습니다.
ErrorStopping=ID가 '({1})'인 프로세스 일치 경로 '{0}'을 중지하지 못했습니다. 메시지: {2}.
ErrorStarting=프로세스 일치 경로 '{0}'을(를) 시작하지 못했습니다. 메시지: {1}.
StartingProcessWhatif=Start-Process
ProcessNotFound=프로세스 일치 경로 '{0}'을(를) 찾을 수 없습니다.
PathShouldBeAbsolute=경로는 절대 경로여야 함
PathShouldExist=경로가 존재해야 함
ParameterShouldNotBeSpecified=매개 변수 {0}은(는) 지정하지 않아야 합니다.
FailureWaitingForProcessesToStart=프로세스가 시작될 때까지 기다리지 못함
FailureWaitingForProcessesToStop=프로세스가 중지될 때까지 기다리지 못함
ErrorParametersNotSupportedWithCredential=사용자 컨텍스트에서 프로세스를 실행하려고 할 때 StandardOutputPath, StandardInputPath 또는 WorkingDirectory를 지정할 수 없습니다.
VerboseInProcessHandle=프로세스 핸들 {0}에서
ErrorInvalidUserName=사용자 이름 {0}이(가) 유효하지 않습니다.
ErrorRunAsCredentialParameterNotSupported=PsDscRunAsCredential 매개 변수는 프로세스 리소스에서 지원되지 않습니다. '{0}' 사용자로 프로세스를 시작하려면 Credential 매개 변수를 사용하십시오.
ErrorCredentialParameterNotSupportedWithRunAsCredential=PsDscRunAsCredential 매개 변수는 프로세스 리소스에서 지원되지 않으며 Credential 매개 변수와 함께 사용할 수 없습니다. '{0}' 사용자로 프로세스를 시작하려면 PsDscRunAsCredential 매개 변수가 아니라 Credential 매개 변수만 사용하십시오.
###PSLOC
'@
