# Localized	12/07/2019 11:51 AM (GMT)	303:6.40.20520 	MSFT_RoleResourceStrings.psd1
# Localized MSFT_RoleResource.psd1

ConvertFrom-StringData @'
###PSLOC
SetTargetResourceInstallwhatIfMessage={0} 기능을 설치하려고 합니다.
SetTargetResourceUnInstallwhatIfMessage={0} 기능을 제거하려고 합니다.
FeatureNotFoundError=대상 컴퓨터에서 요청한 기능 {0}을(를) 찾을 수 없습니다.
FeatureDiscoveryFailureError=대상 컴퓨터에서 요청된 기능 {0} 정보를 가져오지 못했습니다. 기능 이름에는 와일드카드 패턴이 지원되지 않습니다.
FeatureInstallationFailureError={0} 기능을 설치하지 못했습니다.
FeatureUnInstallationFailureError={0} 기능을 성공적으로 제거하지 못했습니다.
QueryFeature=서버 관리자 cmdlet Get-WindowsFeature를 사용하여 {0} 기능을 쿼리하는 중입니다.
InstallFeature=서버 관리자 cmdlet Add-WindowsFeature를 사용하여 {0} 기능을 설치하는 중입니다.
UninstallFeature=서버 관리자 cmdlet Remove-WindowsFeature를 사용하여 {0} 기능을 제거하는 중입니다.
RestartNeeded=대상 컴퓨터를 다시 시작해야 합니다.
GetTargetResourceStartVerboseMessage={0} 기능에 대한 Get 기능 실행을 시작합니다.
GetTargetResourceEndVerboseMessage={0} 기능에 대한 Get 기능 실행을 종료합니다.
SetTargetResourceStartVerboseMessage={0} 기능에 대한 Set 기능 실행을 시작합니다.
SetTargetResourceEndVerboseMessage={0} 기능에 대한 Set 기능 실행을 종료합니다.
TestTargetResourceStartVerboseMessage={0} 기능에 대한 Test 기능 실행을 시작합니다.
TestTargetResourceEndVerboseMessage={0} 기능에 대한 Test 기능 실행을 종료합니다.
ServerManagerModuleNotFoundDebugMessage=ServerManager 모듈이 컴퓨터에 설치되어 있지 않습니다.
SkuNotSupported=PowerShell 원하는 상태 구성을 사용한 역할 및 기능 설치는 서버 SKU에서만 지원됩니다. 클라이언트 SKU에서는 지원되지 않습니다.
SourcePropertyNotSupportedDebugMessage=이 운영 체제에서는 MSFT_RoleResource의 Source 속성이 지원되지 않으며 무시되었습니다.
EnableServerManagerPSHCmdletsFeature=Windows Server 2008R2 핵심 운영 체제 검색됨: ServerManager-PSH-Cmdlets 기능이 사용하도록 설정되었습니다.
UninstallSuccess={0} 기능을 제거했습니다.
InstallSuccess={0} 기능을 설치했습니다.
###PSLOC

'@
