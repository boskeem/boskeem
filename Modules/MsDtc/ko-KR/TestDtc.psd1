# Localized	12/07/2019 11:41 AM (GMT)	303:6.40.20520 	TestDtc.psd1
ConvertFrom-StringData @'
       
###PSLOC start localizing

FirewallRuleEnabled="{0}: {1}에 대한 방화벽 규칙이 사용됩니다."
FirewallRuleDisabled="{0}: {1}에 대한 방화벽 규칙이 사용되지 않습니다. 이 컴퓨터는 네트워크 트랜잭션에 참가할 수 없습니다."
CmdletFailed="{0} cmdlet이 실패했습니다. {1} 모듈이 설치되어 있는지 확인하십시오."
InvalidLocalComputer="{0}은(는) 올바른 로컬 컴퓨터 이름이 아닙니다."
RPCEndpointMapper="RPC 엔드포인트 매퍼"
DtcIncomingConnection="DTC 들어오는 연결"
DtcOutgoingConnection="DTC 나가는 연결"
MatchingDtcNotFound="VirtualServerName이 {0}인 DTC 인스턴스가 없습니다."
InboundDisabled="{0}: 인바운드 트랜잭션은 허용되지 않으며 이 컴퓨터는 네트워크 트랜잭션에 참가할 수 없습니다."
OutboundDisabled="{0}: 아웃바운드 트랜잭션은 허용되지 않으며 이 컴퓨터는 네트워크 트랜잭션에 참가할 수 없습니다."
OSVersion="{0} 운영 체제 버전: {1}."
OSQueryFailed="{0}의 운영 체제를 쿼리하지 못했습니다."
VersionNotSupported="이 cmdlet으로는 {0}보다 낮은 Windows 버전에서 DTC를 테스트할 수 없습니다."
FailedToCreateCimSession="{0}에 대한 CIM 세션을 만들지 못했습니다."
NotARemoteComputer="{0}은(는) 원격 컴퓨터가 아닙니다."
PingingSucceeded="{1}에서 컴퓨터 {0}에 대한 ping에 성공했습니다."
PingingFailed="{1}에서 컴퓨터 {0}에 대한 ping에 실패했습니다."
SameCids="{1} 및 {2}의 {0} CID가 같습니다. 각 컴퓨터에 대해 CID는 고유해야 합니다."
DiagnosticTestPrompt="이 진단 테스트는 {0}과(와) {1} 간 트랜잭션 전파를 수행하려고 시도합니다. 이 테스트를 수행하려면 테스트 리소스 관리자가 네트워크 트랜잭션에 참가할 수 있도록 {0}에 서 TCP 포트가 열려 있어야 합니다."
DefaultPortDescription="기본 포트는 {0}입니다. 'ResourceManagerPort' 매개 변수를 사용하여 기본 포트를 변경하고 테스트를 다시 실행할 수 있습니다."
PortDescription="'ResourceManagerPort'로 {0}을(를) 지정했습니다."
FirewallRequest="테스트를 진행하려면 방화벽에서 포트 {0}을(를) 여십시오."
QueryText="테스트를 진행하시겠습니까?"
InvalidDefaultCluster="{0}은(는) 이 컴퓨터에 구성된 기본 DTC의 가상 서버 이름이 아닙니다. 'Set-DtcClusterDefault' cmdlet을 사용하여 이 컴퓨터의 기본 DTC를 구성할 수 있습니다."
InvalidDefault="{0}은(는) 이 컴퓨터에 구성된 기본 DTC의 가상 서버 이름이 아닙니다. 'Set-DtcDefault' cmdlet을 사용하여 이 컴퓨터의 기본 DTC를 구성할 수 있습니다."
NeedDtcSecurityFix="트랜잭션 전파 테스트를 완료하려면 DTC 보안 설정 및 방화벽 설정을 수정해야 합니다."
StartResourceManagerFailed="테스트 리소스 관리자를 만들지 못했습니다."
ResourceManagerStarted="테스트 리소스 관리자가 시작되었습니다."
PSSessionCreated="{0}에 대한 새 PSSession을 만들었습니다."
TransactionPropagated="{2} 전파를 사용하여 {0}에서 {1}(으)로 트랜잭션이 전파되었습니다."
TransactionPropagationFailed="{2} 전파를 사용하여 {0}에서 {1}(으)로 트랜잭션을 전파하지 못했습니다."
TestRMVerboseLog="테스트 리소스 관리자 자세한 정보 표시 로그:"
TestRMWarningLog="테스트 리소스 관리자 경고 로그:"
InvalidParameters="LocalComputerName 또는 RemoteComputerName 매개 변수 중 적어도 하나를 지정해야 합니다."

###PSLOC
'@
