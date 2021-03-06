# Localized	12/07/2019 11:49 AM (GMT)	303:6.40.20520 	Microsoft.PowerShell.ODataUtilsStrings.psd1
# Localized PSODataUtils.psd1

ConvertFrom-StringData @'
###PSLOC
SelectedAdapter='{0}'을(를) 도트 소싱하는 중입니다.
ArchitectureNotSupported=이 모듈은 프로세서 아키텍처({0})에서 지원되지 않습니다.
ArguementNullError='{0}'이(가) '{1}'에서 $null을 가리키므로 프록시를 생성하지 못했습니다.
EmptyMetadata=메타데이터 읽기가 비어 있습니다. URL: {0}.
InvalidEndpointAddress=잘못된 끝점 주소({0})입니다. 이 끝점 주소에 액세스하는 동안 상태 코드가 '{1}'인 웹 응답을 받았습니다.
NoEntitySets=URI '{0}'의 메타데이터에 엔터티 집합이 포함되어 있지 않습니다. 출력이 기록되지 않습니다.
NoEntityTypes=URI '{0}'의 메타데이터에 엔터티 유형이 포함되어 있지 않습니다. 출력이 기록되지 않습니다.
MetadataUriDoesNotExist=URI '{0}'에 지정된 메타데이터가 없습니다. 출력이 기록되지 않습니다.
InValidIdentifierInMetadata=URI '{0}'에 지정된 메타데이터에 잘못된 식별자 '{1}'이(가) 포함되어 있습니다. 프록시를 만드는 동안 생성되는 복합 형식에서는 유효한 C# 식별자만 지원됩니다.
InValidMetadata=URI '{0}'에서 지정된 메타데이터를 처리하지 못했습니다. 출력이 기록되지 않습니다.
InValidXmlInMetadata=URI '{0}'에 지정된 메타데이터에 잘못된 XML이 포함되어 있습니다. 출력이 기록되지 않습니다.
ODataVersionNotFound=URI '{0}'에 지정된 메타데이터에 OData 버전이 없습니다. 출력이 기록되지 않습니다.
ODataVersionNotSupported=URI '{1}'에 있는 메타데이터에 지정된 OData 버전 '{0}'은 지원되지 않습니다. 프록시를 생성하는 중에는 '{2}' 및 '{3}' 사이의 OData 버전만 '{4}'에서 지원됩니다. 출력이 기록되지 않습니다.
InValidSchemaNamespace=URI '{0}'에 지정된 메타데이터가 잘못되었습니다. 스키마의 Namespace 특성 값은 NULL이거나 비어 있을 수 없습니다.
InValidSchemaNamespaceConflictWithClassName=URI '{0}'에 지정된 메타데이터에 잘못된 네임스페이스 {1} 이름이 포함되어 있으며 다른 형식 이름과 충돌합니다. 컴파일 오류를 방지하기 위해 {1}이(가) {2}(으)로 변경됩니다.
InValidSchemaNamespaceContainsInvalidChars=URI '{0}'에 지정된 메타데이터에 점과 숫자의 조합이 포함된 잘못된 네임스페이스 이름 {1}이(가) 있으며, 이는 .Net에서 허용되지 않습니다. 컴파일 오류를 방지하기 위해 {1}이(가) {2}(으)로 변경됩니다.
InValidUri=URI '{0}'이(가) 잘못되었습니다. 출력이 기록되지 않습니다.
RedfishNotEnabled=이 버전의 Microsoft.PowerShell.ODataUtils는 Redfish를 지원하지 않습니다. ‘update-module Microsoft.PowerShell.ODataUtils’를 실행하여 Redfish 지원을 다운로드하세요.
EntitySetUndefinedType=URI '{0}'의 메타데이터에 엔터티 집합 '{1}'의 유형이 포함되어 있지 않습니다. 출력이 기록되지 않습니다.
XmlWriterInitializationError={0} CDXML 모듈을 쓰기 위해 XmlWriter를 시작하는 동안 오류가 발생했습니다.
EmptySchema=Edmx.DataServices.Schema 노드는 null이 아니어야 합니다.
VerboseReadingMetadata=URI {0}에서 메타데이터를 읽고 있습니다.
VerboseParsingMetadata=메타데이터를 구문 분석하는 중...
VerboseVerifyingMetadata=메타데이터를 검증하는 중...
VerboseSavingModule=출력 모듈을 {0} 경로에 저장하는 중입니다.
VerboseSavedCDXML={0}에 대한 CDXML 모듈을 {1}에 저장했습니다.
VerboseSavedServiceActions=서비스 작업 CDXML 모듈을 {0}에 저장했습니다.
VerboseSavedModuleManifest=모듈 매니페스트를 '{0}' 에 저장했습니다.
AssociationNotFound=Metadata.Associations에서 {0} 연결을 찾을 수 없습니다.
TooManyMatchingAssociationTypes=Metadata.Associations에 {0}개의 {1} 연결이 있습니다. 하나만 필요합니다.
ZeroMatchingAssociationTypes={1} 연결에서 탐색 속성 {0}을(를) 찾을 수 없습니다.
WrongCountEntitySet=EntityType {0}에 대해 하나의 EntitySet만 필요한데 {1}개가 있습니다.
EntityNameConflictError=여러 EntitySets가 동일한 EntityType에 매핑되는 경우 프록시 만들기가 지원되지 않습니다. URL '{0}'에 있는 메타데이터에는 동일한 EntityType '{3}'에 매핑된 EntitySets '{1}' 및 '{2}'이(가) 포함되어 있습니다.
VerboseSavedTypeDefinationModule=형식 정의 모듈 '{0}'을(를) '{1}'에 저장했습니다.
VerboseAddingTypeDefinationToGeneratedModule='{0}'에 대한 형식 정의를 '{1}' 모듈에 추가하고 있습니다.
OutputPathNotFound='{0}' 경로의 일부를 찾을 수 없습니다.
ModuleAlreadyExistsAndForceParameterIsNotSpecified='{0}' 디렉터리가 이미 있습니다. 디렉터리와 디렉터리 내 파일을 덮어쓰려면 -Force 매개 변수를 사용하십시오.
InvalidOutputModulePath=-OutputModule 매개 변수에 지정된 '{0}' 경로에 모듈 이름이 포함되어 있지 않습니다.
OutputModulePathIsNotUnique=-OutputModule 매개 변수에 지정된 '{0}' 경로가 파일 시스템의 여러 경로로 확인됩니다. -OutputModule 매개 변수에 고유한 파일 시스템 경로를 제공하십시오.
OutputModulePathIsNotFileSystemPath=-OutputModule 매개 변수에 지정된 '{0}' 경로는 파일 시스템이 아닙니다. -OutputModule 매개 변수에 고유한 파일 시스템 경로를 제공하십시오.
SkipEntitySetProxyCreation=엔터티 형식 '{1}'에 포함된 '{2}' 속성이 생성된 cmdlet의 기본 속성 중 하나와 충돌하기 때문에 엔터티 집합 '{0}'에 대한 CDXML 모듈 만들기를 건너뛰었습니다.
EntitySetProxyCreationWithWarning=엔터티 집합 '{0}'에 대한 CDXML 모듈을 만들었지만 엔터티 형식 '{2}'에 포함된 '{1}' 속성이 생성된 cmdlet의 기본 속성 중 하나와 충돌합니다.
SkipEntitySetConflictCommandCreation=내보낸 명령 '{1}'이(가) inbox 명령과 충돌하기 때문에 엔터티 집합 '{0}'에 대한 CDXML 모듈 만들기를 건너뛰었습니다.
EntitySetConflictCommandCreationWithWarning=엔터티 집합 '{0}'에 대한 CDXML 모듈을 만들었지만 포함된 '{1}' 명령이 inbox 명령과 충돌합니다.
SkipConflictServiceActionCommandCreation=내보낸 명령 '{1}'이(가) inbox 명령과 충돌하기 때문에 서비스 작업 '{0}'에 대한 CDXML 모듈 만들기를 건너뛰었습니다.
ConflictServiceActionCommandCreationWithWarning=서비스 작업 '{0}'에 대한 CDXML 모듈을 만들었지만 포함된 '{1}' 명령이 inbox 명령과 충돌합니다.
AllowUnsecureConnectionMessage=cmdlet '{0}'에서 URI '{1}'을(를) 통해 OData 끝점에 안전하지 않은 연결을 설정하려고 합니다. -{2} 매개 변수에 보안 URI를 제공하거나, 현재 URI를 사용하려는 경우 -AllowUnsecureConnection 스위치 매개 변수를 사용하십시오.
ProgressBarMessage=URI '{0}'에 OData 끝점에 대한 프록시를 만들고 있습니다.
###PSLOC

'@
