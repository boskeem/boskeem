# Localized	12/07/2019 11:50 AM (GMT)	303:6.40.20520 	NetworkSwitchManager.Resource.psd1
#################################################################
#                                                               #
#   Module Name: NetworkSwitchManager.Resources.psd1            #
#                                                               #
#   Description: Network switch manager localized strings       #
#                                                               #
#   Copyright (c) Microsoft Corporation. All rights reserved.   #
#                                                               #
#################################################################

ConvertFrom-StringData @'
###PSLOC
ErrorMessageNoTarget={0}에서 오류가 발생했습니다. 유효한 CIM 세션을 사용 중인지, 이더넷 스위치 프로필이 올바르게 등록되어 있는지 확인하십시오. 입력 개체를 전달하는 경우 적절한 유형의 유효한 인스턴스인지 확인하십시오. 기본 문제에 대한 자세한 내용은 이 오류 레코드의 예외 멤버를 참조하십시오.
ErrorMessageTarget={1}을(를) 처리하는 동안 {0}에서 오류가 발생했습니다. 유효한 CIM 세션을 사용 중인지, 이더넷 스위치 프로필이 올바르게 등록되어 있는지 확인하십시오. 입력 개체를 전달하는 경우 적절한 유형의 유효한 인스턴스인지 확인하십시오. 기본 문제에 대한 자세한 내용은 이 오류 레코드의 예외 멤버를 참조하십시오.
WarningMessageNoTarget={0}에서 경고가 발생했습니다. {1}.
WarningMessageTarget={1}을(를) 처리하는 동안 {0}에서 경고가 발생했습니다. {2}.
UnknownError=알 수 없는 오류가 발생했습니다. 오류 코드 {0}.
NoValidAssociatedSwitch=등록된 이더넷 스위치 프로필이 규격 스위치와 연결되어 있지 않습니다. 사용 중인 스위치를 이더넷 스위치 프로필에 규격으로 등록하십시오.
NoValidAssociatedNamespace=이더넷 스위치 프로필에 규격으로 등록된 스위치가 유효한 네임스페이스와 연결되어 있지 않습니다. 스위치 구현 및 등록을 검증하십시오.
NoValidRegisteredProfile=이더넷 스위치 프로필이 root/interop, interop, /root/interop 또는 /interop에 등록되어 있지 않습니다. 다음 네임스페이스 중 하나에 이더넷 스위치 프로필을 등록하십시오.
NoMatchingInstance=검색 조건과 일치하는 인스턴스를 찾을 수 없습니다. {0} = {1}.
###PSLOC
'@
