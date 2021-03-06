# Localized	12/07/2019 11:48 AM (GMT)	303:6.40.20520 	ArchiveResources.psd1
# Localized ArchiveResources.psd1

ConvertFrom-StringData @'
###PSLOC
PathNotFoundError='{0}' 경로가 없거나 유효한 파일 시스템 경로가 아닙니다.
ExpandArchiveInValidDestinationPath='{0}' 경로는 유효한 파일 시스템 디렉터리 경로가 아닙니다.
InvalidZipFileExtensionError={0}은(는) 지원되는 보관 파일 형식이 아닙니다. 지원되는 보관 파일 형식은 {1}뿐입니다.
ArchiveFileIsReadOnly=보관 파일 {0}의 특성이 '읽기 전용'으로 설정되어 있어 업데이트할 수 없습니다. 기존 보관 파일을 업데이트하려는 경우 보관 파일에서 '읽기 전용' 특성을 제거하거나 -Force 매개 변수를 사용하여 새 보관 파일을 재정의하고 만드십시오.
ZipFileExistError=보관 파일 {0}이(가) 이미 있습니다. -Update 매개 변수를 사용하여 기존 보관 파일을 업데이트하거나 -Force 매개 변수를 사용하여 기존 보관 파일을 덮어쓰십시오.
DuplicatePathFoundError={0} 매개 변수에 대한 입력에 중복 경로 '{1}'이(가) 포함되어 있습니다. {2} 매개 변수에 대한 입력으로 고유한 경로 집합을 제공하십시오.
ArchiveFileIsEmpty=보관 파일 {0}이(가) 비어 있습니다.
CompressProgressBarText=보관 파일 '{0}'을(를) 만드는 중...
ExpandProgressBarText=보관 파일 '{0}' 확장을 진행하는 중...
AppendArchiveFileExtensionMessage=DestinationPath 매개 변수에 제공된 보관 파일 경로 '{0}'에는 .zip 확장명이 포함되어 있지 않습니다. 따라서 제공한 DestinationPath 경로에 .zip이 추가되며 '{1}'에 보관 파일을 만듭니다.
AddItemtoArchiveFile='{0}'을(를) 추가 중입니다.
BadArchiveEntry=잘못된 보관 항목 ' {0} '으로 처리할 수 없습니다.
CreateFileAtExpandedPath='{0}'을(를) 만들었습니다.
InvalidArchiveFilePathError={1} 매개 변수에 대한 입력으로 지정된 보관 파일 경로 '{0}'이(가) 여러 개의 파일 시스템 경로로 확인됩니다. 보관 파일을 만들어야 하는 고유한 경로를 {2} 매개 변수에 제공하십시오.
InvalidExpandedDirPathError=DestinationPath 매개 변수에 대한 입력으로 지정된 디렉터리 경로 '{0}'이(가) 여러 개의 파일 시스템 경로로 확인됩니다. 보관 파일 콘텐츠를 확장해야 하는 고유한 경로를 Destination 매개 변수에 제공하십시오.
FileExistsError='{2}' 파일이 이미 있으므로 보관 파일 '{1}' 콘텐츠를 확장하는 동안 '{0}' 파일을 만들지 못했습니다. 보관 파일을 확장할 때 기존 디렉터리 '{3}' 콘텐츠를 덮어쓰려는 경우 -Force 매개 변수를 사용하십시오.
DeleteArchiveFile=부분 생성된 보관 파일 '{0}'은(는) 사용할 수 없으므로 삭제되었습니다.
InvalidDestinationPath=대상 경로 '{0}'에 유효한 보관 파일 이름이 포함되어 있지 않습니다.
PreparingToCompressVerboseMessage=압축 준비 중...
PreparingToExpandVerboseMessage=확장 준비 중...
###PSLOC
'@
