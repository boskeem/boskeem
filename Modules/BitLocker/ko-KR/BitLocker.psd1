# Localized	12/07/2019 11:55 AM (GMT)	303:6.40.20520 	BitLockerStrings.psd1
ConvertFrom-StringData -stringdata @' 
###PSLOC
ErrorMountPointNotFound={0}에 연결된 BitLocker 볼륨이 없습니다.
ErrorVolumeNotFound=장치 ID: {0}에 해당 볼륨이 없습니다.
ErrorVolumeBoundAlready=이 키 보호기는 볼륨을 자동으로 잠금 해제하는 데 사용되므로 삭제할 수 없습니다.
ErrorOperatingSystemMountPointNotFound=운영 체제 볼륨을 찾을 수 없습니다.
WarningUsedSpaceOnlyAndHardwareEncryption=UsedSpaceOnly 스위치 및 HardwareEncryption 스위치는 함께 사용할 수 없습니다. UsedSpaceOnly를 무시합니다.
ErrorExternalKeyOrPasswordRequired=유효한 TPM 없이 운영 체제 볼륨에서 BitLocker를 사용하려면 외부 키 또는 암호 보호기가 필요합니다.
WarningWriteDownRecoveryPassword=해결 방법:{1}{1}1. 이 숫자 복구 암호를 컴퓨터가 아닌 안전한 장소에 보관합니다.{1}{1}{0}{1}{1}데이터 손실을 막으려면 이 암호를 즉시 저장하십시오. 이 암호를 사용하면 암호화된 볼륨의 잠금을 해제할 수 있습니다.
WarningWriteDownRecoveryPasswordInsertExternalKeyRestart=해결 방법:{1}{1}1. 이 숫자 복구 암호를 컴퓨터가 아닌 안전한 장소에 보관합니다.{1}{1}{0}{1}{1}데이터 손실을 막으려면 이 암호를 즉시 저장하십시오. 이 암호를 사용하면 암호화된 볼륨의 잠금을 해제할 수 있습니다.{1}2. 외부 키 파일이 있는 USB 플래시 드라이브를 컴퓨터에 삽입합니다.{1}3. 하드웨어 테스트를 실행하기 위해 컴퓨터를 다시 시작합니다.{1}    명령줄 지침을 보려면 get-help Restart-Computer를 입력하십시오.
WarningWriteDownRecoveryPasswordRestart=해결 방법:{1}{1}1. 이 숫자 복구 암호를 컴퓨터가 아닌 안전한 장소에 보관합니다.{1}{1}{0}{1}{1}데이터 손실을 막으려면 이 암호를 즉시 저장하십시오. 이 암호를 사용하면 암호화된 볼륨의 잠금을 해제할 수 있습니다.{1}2. 하드웨어 테스트를 실행하기 위해 컴퓨터를 다시 시작합니다.{1}    명령줄 지침을 보려면 get-help Restart-Computer를 입력하십시오.
WarningHardwareTestFailed=오류: 코드 0x%1!08x! 때문에 하드웨어를 테스트하지 못했습니다. 모든 키{0}보호기가 제거되었습니다.{0}{0}하드웨어를 테스트하지 못한 원인은 다음과 같습니다.{0}{0}1. 외부 키 파일이 있는 USB 플래시 드라이브가 없습니다.{0}{0}- 외부 키 파일이 있는 USB 플래시 드라이버를 컴퓨터에 삽입하십시오.{0}- 이 오류가 지속되면 부팅하는 동안 컴퓨터에서 USB 드라이브를 {0}  읽을 수 없습니다. 부팅하는 동안 외부 키를 사용하여 OS 볼륨의{0}  잠금을 해제하지 못할 수 있습니다.{0}{0}2. USB 플래시 드라이브의 외부 키 파일이 손상되었습니다.{0}{0}- 다른 USB 플래시 드라이브를 사용하여 외부 키 파일을 저장하십시오.{0}{0}3. TPM이 꺼져 있습니다.{0}{0}- TPM(신뢰할 수 있는 플랫폼 모듈)을 관리하려면{0}  TPM 관리 MMC 스냅인 또는 TPM 관리 PowerShell cmdlet을 사용하십시오.{0}{0}4. TPM이 OS 부팅 구성 요소가 변경되었음을 감지했습니다.{0}{0}- 컴퓨터에서 부팅 가능한 CD 또는 DVD를 모두 제거하십시오.{0}- 이 오류가 지속되면 최신 펌웨어 및 BIOS 업그레이드가{0}  설치되어 있는지 확인하고 TPM이 제대로 작동하는지 확인하십시오.{0}{0}5. 제공된 PIN이 잘못되었습니다.{0}{0}6. TPM SRK(저장소 루트 키)의 권한 부여 값이 호환되지 않습니다.{0}{0}- 이 값을 다시 설정하려면 TPM 초기화 마법사를 실행하십시오.{0}{0}해결 방법:{0}{0}1. 위의 하드웨어 테스트 오류를 해결합니다.{0}2. 명령을 다시 실행하여 BitLocker를 켭니다.{0}
WarningInsertExternalKeyRestart=해결 방법:{0}{0}1. 외부 키 파일이 있는 USB 플래시 드라이브를 컴퓨터에 삽입합니다.{0}2. 하드웨어 테스트를 실행하기 위해 컴퓨터를 다시 시작합니다.{0}    명령줄 지침을 보려면 get-help Restart-Computer를 입력하십시오.
WarningRestart=해결 방법:{0}{0}1. 하드웨어 테스트를 실행하기 위해 컴퓨터를 다시 시작합니다.{0}    명령줄 지침을 보려면 get-help Restart-Computer를 입력하십시오.
ErrorSidProtectorRequiresAdditionalRecoveryProtector=오류: 이 볼륨에서 SID 기반 ID 보호기를 사용하여 BitLocker를 켜려면 복구에 대해 추가 보호기를 하나 이상 제공해야 합니다.
ErrorRemoveDraProtector=데이터 복구 에이전트 인증서를 제거하려면 인증서 스냅인을 사용해야 합니다.
ErrorRemoveNkpProtector=Network Unlock을 사용하지 않도록 설정하려면 BitLocker 드라이브 암호화 그룹 정책 설정 "시작 시 네트워크 잠금 해제 허용" 내에서 설정하거나 도메인 컨트롤러의 공개 키 정책 그룹 정책 설정 "BitLocker 드라이브 암호화 네트워크 잠금 해제 인증서"를 제거해야 합니다.
PasswordPrompt=암호 입력:
ConfirmPasswordPrompt=암호 확인:
NoMatchPassword=이러한 암호가 일치하지 않습니다. 다시 입력하십시오.
PinPrompt=PIN 입력:
ConfirmPinPrompt=PIN 확인:
NoMatchPin=이러한 PIN이 일치하지 않습니다. 다시 입력하십시오.
ErrorGroupPolicyDisabledBackup=그룹 정책에서 복구 정보를 Active Directory에 저장하는 것을 허용하지 않습니다. 작업이 시도되지 않았습니다.
'@
