# Localized	12/07/2019 11:49 AM (GMT)	303:6.40.20520 	MSFT_GroupResource.strings.psd1
# Localized resources for MSFT_GroupResource

ConvertFrom-StringData @'
###PSLOC
GroupWithName=그룹: {0}
RemoveOperation=제거
AddOperation=추가
SetOperation=설정
GroupCreated={0} 그룹을 성공적으로 만들었습니다.
GroupUpdated={0} 그룹 속성을 성공적으로 업데이트했습니다.
GroupRemoved={0} 그룹을 성공적으로 제거했습니다.
NoConfigurationRequired={0} 그룹은 필요한 속성을 가진 이 노드에 있습니다. 작업이 필요하지 않습니다.
NoConfigurationRequiredGroupDoesNotExist={0} 그룹은 이 노드에 없습니다. 작업이 필요하지 않습니다.
CouldNotFindPrincipal=제공된 이름 [{0}]을(를) 가진 보안 주체를 찾을 수 없습니다.
MembersAndIncludeExcludeConflict={0} 매개 변수와 {1} 및/또는 {2} 매개 변수가 충돌합니다. {0} 매개 변수는 {1} 및 {2} 매개 변수의 어떤 조합에도 사용하지 않아야 합니다.
MembersIsNull=Members 매개 변수 값이 null입니다. {1} 및 {2}을(를) 둘 다 제공하지 않을 경우 {0} 매개 변수를 제공해야 합니다.
MembersIsEmpty=Members 매개 변수가 비어 있습니다. 그룹 구성원을 하나 이상 제공해야 합니다.
MemberNotValid=그룹 구성원이 없거나 확인할 수 없습니다. {0}.
IncludeAndExcludeConflict={0} 보안 주체가 {1} 및 {2} 매개 변수 값에 모두 포함되어 있습니다. {1} 및 {2} 매개 변수 값에 모두 동일한 보안 주체를 포함하지 않아야 합니다.
IncludeAndExcludeAreEmpty=MembersToInclude와 MembersToExclude가 둘 다 null이거나 비어 있습니다. 두 매개 변수 중 하나에 구성원을 하나 이상 지정해야 합니다.
InvalidGroupName={0}은(는) 사용할 수 없는 이름입니다. 이름은 마침표 및/또는 공백만으로 구성하거나 {1} 문자를 포함할 수 없습니다.
GroupExists=이름이 {0}인 그룹이 있습니다.
GroupDoesNotExist=이름이 {0}인 그룹이 없습니다.
PropertyMismatch={0} 속성의 값이 {1}이어야 하는데 {2}입니다.
MembersNumberMismatch={0} 속성. 제공한 고유 그룹 구성원 수 {1}이(가) 실제 그룹 구성원 수 {2}과(와) 다릅니다.
MembersMemberMismatch=제공한 {1} 매개 변수의 {0} 구성원 중 기존 그룹 {2}에 일치 항목이 존재하지 않는 구성원이 하나 이상 있습니다.
MemberToExcludeMatch=제공한 {1} 매개 변수의 {0} 구성원 중 기존 그룹 {2}에 일치 항목이 존재하는 구성원이 하나 이상 있습니다.
ResolvingLocalAccount=로컬 계정으로 {0}을(를) 확인하는 중입니다.
ResolvingDomainAccount={1} 도메인에서 {0}을(를) 확인하는 중입니다.
ResolvingDomainAccountWithTrust=도메인 트러스트를 사용하여 {0}을(를) 확인하는 중입니다.
DomainCredentialsRequired=도메인 계정 {0}을(를) 확인하려면 자격 증명이 필요합니다.
UnableToResolveAccount='{0}' 계정을 확인할 수 없습니다. 다음 메시지를 표시하며 실패했습니다. {1} (오류 코드={2})
###PSLOC

'@
