# Localized	12/07/2019 11:43 AM (GMT)	303:6.40.20520 	PackageProvider.psd1
# Localized PackageProvider.psd1

ConvertFrom-StringData @'
###PSLOC
InvalidIdentifyingNumber=지정된 IdentifyingNumber({0})는 올바른 Guid가 아닙니다.
InvalidPath=지정된 Path({0})는 올바른 형식이 아닙니다. 올바른 형식은 로컬 경로, UNC 및 HTTP입니다.
InvalidNameOrId=지정한 Name({0}) 및 IdentifyingNumber({1})가 MSI 파일에 있는 Name({2}) 및 IdentifyingNumber({3})와 일치하지 않습니다.
NeedsMoreInfo=Name 또는 ProductId가 필요합니다.
InvalidBinaryType=지정된 Path({0})는 EXE 또는 MSI 파일을 지정하는 데 표시되지 않으며 그러한 지정은 지원되지 않습니다.
CouldNotOpenLog=지정된 LogPath({0})를 열 수 없습니다.
CouldNotStartProcess={0} 프로세스를 시작할 수 없습니다.
UnexpectedReturnCode=반환 코드 {0}이(가) 필요합니다. 구성이 올바르지 않은 것 같습니다.
PathDoesNotExist=지정된 Path({0})를 찾을 수 없습니다.
CouldNotOpenDestFile=쓰기 위해 {0} 파일을 열 수 없습니다.
CouldNotGetHttpStream={1} 파일에 대한 {0} 스트림을 가져올 수 없습니다.
ErrorCopyingDataToFile={0}의 콘텐츠를 {1}에 쓰는 동안 오류가 발생했습니다.
PackageConfigurationComplete=패키지 구성을 마쳤습니다.
PackageConfigurationStarting=패키지 구성을 시작하는 중입니다.
InstalledPackage=설치된 패키지
UninstalledPackage=제거된 패키지
NoChangeRequired=필요한 상태의 패키지가 있습니다. 작업이 필요하지 않습니다.
RemoveExistingLogFile=기존 로그 파일 제거
CreateLogFile=로그 파일 만들기
MountSharePath=미디어를 가져올 마운트 공유
DownloadHTTPFile=HTTP 또는 HTTPS를 통해 미디어 다운로드
StartingProcessMessage={1} 인수를 사용하여 {0} 프로세스를 시작하는 중
RemoveDownloadedFile=다운로드한 파일 제거
PackageInstalled=패키지가 설치되었습니다.
PackageUninstalled=패키지가 제거되었습니다.
MachineRequiresReboot=컴퓨터를 다시 부팅해야 합니다.
PackageDoesNotAppearInstalled={0} 패키지가 설치되어 있지 않습니다.
PackageAppearsInstalled={0} 패키지가 설치되어 있습니다.
PostValidationError={0}의 패키지가 설치되었지만, 지정된 ProductId 및/또는 Name이 패키지 세부 정보와 일치하지 않습니다.
ValidateStandardArgumentsPathwasPath=Validate-StandardArguments, 경로는 {0}입니다.
TheurischemewasuriScheme=URI 스키마는 {0}입니다.
ThepathextensionwaspathExt=경로 확장은 {0}입니다.
ParsingProductIdasanidentifyingNumber={0}을(를) identifyingNumber로 구문 분석하는 중
ParsedProductIdasidentifyingNumber={0}을(를) {1}(으)로 구문 분석했습니다.
EnsureisEnsure=Ensure는 {0}입니다.
productisproduct={0} 제품이 있습니다.
productasbooleanis=product as boolean은 {0}입니다.
Creatingcachelocation=캐시 위치를 만드는 중
NeedtodownloadfilefromschemedestinationwillbedestName={0}에서 파일을 다운로드해야 합니다. 대상은 {1}입니다.
Creatingthedestinationcachefile=대상 캐시 파일을 만드는 중
Creatingtheschemestream={0} 스트림을 만드는 중
Settingdefaultcredential=기본 자격 증명을 설정하는 중
Settingauthenticationlevel=인증 수준을 설정하는 중
Ignoringbadcertificates=잘못된 인증서를 무시하는 중
Gettingtheschemeresponsestream={0} 응답 스트림을 가져오는 중
ErrorOutString=오류: {0}
Copyingtheschemestreambytestothediskcache={0} 스트림 바이트를 디스크 캐시로 복사하는 중
Redirectingpackagepathtocachefilelocation=패키지 경로를 캐시 파일 위치로 리디렉션하는 중
ThebinaryisanEXE=이진은 EXE입니다.
Userhasrequestedloggingneedtoattacheventhandlerstotheprocess=사용자가 로깅을 요청했습니다. 프로세스에 이벤트 처리기를 연결해야 합니다.
StartingwithstartInfoFileNamestartInfoArguments={1}을(를) 사용하여 {0} 시작 중
###PSLOC

'@
