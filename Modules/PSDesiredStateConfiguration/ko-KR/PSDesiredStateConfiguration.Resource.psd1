# Localized	12/07/2019 11:43 AM (GMT)	303:6.40.20520 	PSDesiredStateConfiguration.Resource.psd1
# Localized	04/21/2015 09:07 AM (GMT)	303:4.80.0411 	PSDesiredStateConfiguration.Resource.psd1
# Localized PSDesiredStateConfigurationResource.psd1

ConvertFrom-StringData @'
###PSLOC
CheckSumFileExists='{0}' 파일이 이미 있습니다. -Force 매개 변수를 지정하여 기존 체크섬 파일을 덮어쓰십시오.
CreateChecksumFile=체크섬 파일 '{0}' 만들기
OverwriteChecksumFile=체크섬 파일 '{0}' 덮어쓰기
OutpathConflict=(오류) '{0}' 디렉터리를 만들 수 없습니다. 같은 이름을 가진 파일이 있습니다.
InvalidConfigPath=(오류) 잘못된 구성 경로 '{0}'이(가) 지정되었습니다.
InvalidOutpath=(오류) 잘못된 OutPath '{0}'이(가) 지정되었습니다.
InvalidConfigurationName=잘못된 구성 이름 '{0}'을(를) 지정했습니다. 표준 이름에는 문자(a-z, A-Z), 숫자(0-9), 마침표(.), 하이픈(-), 밑줄(_)만 사용할 수 있습니다. 이름은 null이거나 비워 둘 수 없으며, 문자로 시작해야 합니다.
NoValidConfigFileFound=올바른 구성 파일(mof,zip)이 없습니다.
InputFileNotExist={0} 파일이 없습니다.
FileReadError={0} 파일을 읽는 동안 오류가 발생했습니다.
MatchingFileNotFound=일치하는 파일을 찾을 수 없습니다.
CertificateFileReadError=인증서 파일 {0}을(를) 읽는 중 오류가 발생했습니다.
CertificateStoreReadError={0}에 대한 인증서 저장소를 읽는 동안 오류가 발생했습니다.
CannotCreateOutputPath=잘못된 구성 이름 및 출력 경로 조합: {0}. 출력 매개 변수가 올바른 패스 세그먼트인지 확인하십시오.
ConflictingDuplicateResource='{2}' 노드의 '{0}' 리소스와 '{1}' 리소스 사이에 충돌이 검색되었습니다. 리소스에서 키 속성은 동일하지만 키가 아닌 속성 '{3}'에 차이가 있습니다. '{4}' 값이 '{5}' 값과 일치하지 않습니다. 두 경우 모두에 해당 속성 값이 동일하도록 속성 값을 업데이트하십시오.
ConfiguratonDataNeedAllNodes=ConfigurationData 매개 변수에 AllNodes 속성이 있어야 합니다.
ConfiguratonDataAllNodesNeedHashtable=ConfigurationData 매개 변수 속성 AllNodes는 컬렉션이어야 합니다.
AllNodeNeedToBeHashtable=AllNodes의 모든 요소가 해시 테이블이어야 하며 'NodeName' 속성이 있습니다.
DuplicatedNodeInConfigurationData=전달된 configurationData에 중복된 NodeNames '{0}'이(가) 있습니다.
EncryptedToPlaintextNotAllowed=암호화된 암호를 일반 텍스트로 변환하여 저장하는 것은 권장되지 않습니다. MOF 파일의 자격 증명을 보호하는 방법에 대한 자세한 내용은 MSDN 블로그(https://go.microsoft.com/fwlink/?LinkId=393729)를 참조하세요.
DomainCredentialNotAllowed='{0}' 노드의 도메인 자격 증명을 사용하지 않는 것이 좋습니다. 경고가 표시되지 않도록 '{0}' 노드의 DSC 구성 데이터에 값이 $true인 'PSDscAllowDomainUser' 속성을 추가할 수 있습니다.
NestedNodeNotAllowed=노드 정의는 중첩할 수 없으므로 현재 노드 '{1}' 안에 '{0}' 노드를 정의할 수 없습니다. '{0}' 노드에 대한 정의를 '{2}' 구성의 최상위 수준으로 이동하십시오.
FailToProcessNode='{0}' 노드를 처리하는 동안 예외가 발생했습니다. {1}
LocalHostNodeNotAllowed='{0}' 구성에는 노드와 연결되지 않은 리소스 정의가 이미 하나 이상 있으므로 이 구성에 'localhost' 노드를 정의할 수 없습니다.
InvalidMOFDefinition='{0}' 노드에 대한 잘못된 MOF 정의: {1}
RequiredResourceNotFound='{1}'에 필요한 '{0}' 리소스가 없습니다. 필요한 리소스가 존재하고 이름이 올바른 형식이어야 합니다.
ReferencedManagerNotFound='{1}'에서 참조되는 다운로드 관리자 '{0}'이(가) 없습니다. 참조된 다운로드 관리자가 있고 이름의 형식이 올바른지 확인하십시오.
ReferencedResourceSourceNotFound='{1}'에서 참조된 리소스 리포지토리 '{0}'이(가) 없습니다. 참조된 리소스 리포지토리가 있고 이름의 형식이 올바른지 확인하십시오.
DependsOnLinkTooDeep=DependsOn 링크가 최대 깊이 제한 '{0}'을(를) 초과했습니다.
DependsOnLoopDetected='{0}'에 순환 DependsOn이 있습니다. 순환 참조가 없도록 하십시오.
FailToProcessConfiguration='{0}' 구성을 처리하는 동안 컴파일 오류가 발생했습니다. 오류 스트림에서 보고된 오류를 검토하고 구성 코드를 적절하게 수정하세요.
FailToProcessProperty='{2}' 형식의 '{1}' 속성을 처리하는 동안 {0} 오류가 발생했습니다. {3}
NodeNameIsRequired=노드 이름이 비어 있으므로 노드 처리를 건너뜁니다.
ConvertValueToPropertyFailed='{2}' 속성에 대해 '{0}'을(를) '{1}' 형식으로 변환할 수 없습니다.
ResourceNotFound='{0}' 용어는 {1}의 이름으로 인식되지 않습니다.
GetDscResourceInputName=Get-DscResource 입력 '{0}' 매개 변수 값이 '{1}'입니다.
ResourceNotMatched='{0}' 리소스는 요청된 이름과 일치하지 않으므로 건너뜁니다.
InitializingClassCache=클래스 캐시를 초기화하는 중
LoadingDefaultCimKeywords=기본 CIM 키워드를 로드하는 중
GettingModuleList=모듈 목록을 가져오는 중
CreatingResourceList=리소스 목록을 만드는 중
CreatingResource='{0}' 리소스를 만드는 중입니다.
SchemaFileForResource={0} 리소스에 대한 스키마 파일 이름
UnsupportedReservedKeyword='{0}' 키워드는 이 언어 버전에서 지원되지 않습니다.
UnsupportedReservedProperty='{0}' 속성은 이 언어 버전에서 지원되지 않습니다.
MetaConfigurationHasMoreThanOneLocalConfigurationManager='{0}' 노드에 대한 메타 구성에 LocalConfigurationManager에 대한 정의가 두 개 이상 포함되어 있으며, 이는 허용되지 않습니다.
MetaConfigurationSettingsMissing='{0}' 노드에 대한 설정이 정의되어 있지 않습니다. 이 노드에 대해 기본 빈 설정 정의가 추가됩니다.
ConflictInExclusiveResources=부분 구성 '{0}' 및 '{1}'에 충돌하는 단독 리소스 선언이 있습니다.
ReferencedModuleNotExist=참조된 모듈 '{0}'이(가) 컴퓨터에 없습니다. Get-DscResource를 사용하여 컴퓨터에 있는 항목을 확인하십시오.
ReferencedResourceNotExist=참조된 리소스 '{0}'이(가) 컴퓨터에 없습니다. Get-DscResource를 사용하여 컴퓨터에 있는 항목을 확인하십시오.
ReferencedModuleResourceNotExist=참조된 모듈\\리소스 '{0}'이(가) 컴퓨터에 없습니다. Get-DscResource를 사용하여 컴퓨터에 있는 항목을 확인하십시오.
DuplicatedResourceInModules=참조된 리소스 '{0}'이(가) 컴퓨터의 {1} 모듈과 {2} 모듈에 있습니다. 하나의 모듈에만 있어야 합니다.
CannotConvertStringToBool=값 "System.String"을 "System.Boolean" 형식으로 변환할 수 없습니다. 부울 매개 변수는 $True, $False, 1 또는 0과 같은 부울 값과 숫자만 허용합니다.
NoModulesPresent=시스템에 지정된 모듈 사양을 가진 모듈이 없습니다.
ImportDscResourceWarningForInbuiltResource='{0}' 구성에서 연결된 모듈을 명시적으로 가져오지 않고 기본 제공된 리소스를 하나 이상 로드하고 있습니다. 이 메시지를 표시하지 않으려면 사용자 구성에 Import-DscResource –ModuleName 'PSDesiredStateConfiguration'을 추가하십시오.
PasswordTooLong='{0}' 노드에서 암호에 대한 암호화하는 동안 오류가 발생했습니다. 선택한 인증서를 사용하여 암호화하기에는 입력한 암호가 너무 깁니다. 더 짧은 암호를 사용하거나 키가 더 큰 인증서를 선택하십시오.
HashtableElementTypeNotAllowed='{0}' 형식의 값이 해시 테이블에서 허용되지 않습니다. 지원되는 형식: [String], [Char], [Int64], [UInt64], [Double], [Bool] ,[DateTime] 및 [ScriptBlock].
PullModeWithoutDownloadManager=메타 구성이 DownloadManager를 지정해야 하는 끌어오기 모드로 설정되어 있습니다.
PullModeWithoutConfigurationRepository=메타 구성이 ConfigurationRepository를 지정해야 하는 끌어오기 모드로 설정되어 있습니다.
DownloadManagerWithoutPullMode=새로 고침 모드를 PULL로 설정하지 않고 DownloadManager가 지정되었습니다.
ConfigurationRepositoryWithoutPullMode=새로 고침 모드를 PULL로 설정하지 않고 ConfigurationRepository가 지정되었습니다.
ReferencedPolicyNotDefined=참조된 SignatureValidationPolicy '{0}'이(가) 정의되지 않았습니다. 같은 이름으로 SignatureValidation 블록을 정의하세요.
IncorrectSignatureValidationPolicyFormat=SignatureValidationPolicy에 제공된 값의 형식이 잘못되었습니다. '[SignatureValidation]<이름>' 형식으로 값을 제공하세요.
###PSLOC
'@
