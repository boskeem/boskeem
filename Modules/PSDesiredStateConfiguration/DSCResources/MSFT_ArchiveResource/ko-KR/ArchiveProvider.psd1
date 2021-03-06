# Localized	12/07/2019 11:44 AM (GMT)	303:6.40.20520 	ArchiveProvider.psd1
# Localized ArchiveProvider.psd1

ConvertFrom-StringData @'
###PSLOC
InvalidChecksumArgsMessage=콘텐츠 유효성 검사(Validate 매개 변수)를 요청하지 않고 체크섬을 지정하는 것은 의미가 없습니다.
InvalidDestinationDirectory=지정된 대상 디렉터리 {0}이(가) 존재하지 않거나 디렉터리가 아닙니다.
InvalidSourcePath=지정된 원본 파일 {0}이(가) 존재하지 않거나 디렉터리가 아닙니다.
InvalidNetSourcePath=지정한 원본 파일 {0}은(는) 유효한 순수 원본 경로가 아닙니다.
ErrorOpeningExistingFile=디스크의 {0} 파일을 여는 동안 오류가 발생했습니다. 자세한 내용은 내부 예외를 참조하십시오.
ErrorOpeningArchiveFile=보관 파일 {0}을(를) 여는 동안 오류가 발생했습니다. 자세한 내용은 내부 예외를 참조하십시오.
ItemExistsButIsWrongType=명명된 항목({0})이 있지만 필요한 유형이 아니므로 Force가 지정되지 않았습니다.
ItemExistsButIsIncorrect=원본과 일치하지 않도록 대상 파일 {0}을 확인했지만 Force가 지정되지 않았습니다. 계속할 수 없습니다.
ErrorCopyingToOutstream=보관 파일을 {0}에 복사하는 동안 오류가 발생했습니다.
PackageUninstalled={0}의 보관 파일을 대상 {1}에서 제거했습니다.
PackageInstalled=대상 {1}에 {0}의 보관 파일의 압축을 풀었습니다.
ConfigurationStarted=MSFT_ArchiveResource의 구성을 시작하는 중입니다.
ConfigurationFinished=MSFT_ArchiveResource의 구성을 완료했습니다.
MakeDirectory={0} 디렉터리 만들기
RemoveFileAndRecreateAsDirectory=기존 파일 {0}을(를) 제거하고 동일한 이름을 가진 디렉터리로 바꾸기
RemoveFile={0} 파일 제거
RemoveDirectory={0} 디렉터리 제거
UnzipFile={0}에 보관 파일의 압축 풀기
DestMissingOrIncorrectTypeReason=대상 파일 {0}이(가) 없거나 파일이 아닙니다.
DestHasIncorrectHashvalue=대상 파일 {0}이(가) 존재하지만 해당 체크섬이 원본 파일과 일치하지 않습니다.
DestShouldNotBeThereReason=대상 파일 {0}이(가) 없어야 하는데 존재합니다.
UsingKeyToRetrieveHashValue={0}을(를) 사용하여 해시 값을 검색하는 중
Nocachevaluefound=캐시 값을 찾을 수 없습니다.
Cachevaluefoundreturning=캐시 값을 찾았습니다. {0}을(를) 반환합니다.
CacheCorrupt=캐시를 찾았지만 로드하지 못했습니다. 캐시를 무시합니다.
Usingtmpkeytosavehashvalue={0} {1}을(를) 사용하여 해시 값을 저장하는 중
AbouttocachevalueInputObject={0} 값을 캐시하려고 합니다.
InUpdateCache=Update-Cache에 있음
AddingentryFullNameasacacheentry=캐시 항목으로 {0}을(를) 추가하는 중
UpdatingCacheObject=CacheObject 업데이트 중
Placednewcacheentry=새 캐시 항목을 배치했습니다.
NormalizeChecksumreturningChecksum=Normalize-Checksum에서 {0}을(를) 반환합니다.
PathPathisalreadyaccessiableNomountneeded.={0} 경로에 이미 액세스할 수 있습니다. 탑재할 필요가 없습니다.
Pathpathisnotavalidatenetpath={0} 경로는 유효한 순 경로가 아닙니다.
createpsdrivewithPathpath={0} 경로를 사용하여 psdrive 만들기...
CannotaccessPathPathwithgivenCredential=지정된 자격 증명을 사용하여 {0} 경로에 액세스할 수 없습니다.
Abouttovalidatestandardarguments=표준 인수의 유효성을 검사하려고 합니다.
Goingforcacheentries=캐시 항목을 가져오는 중
Thecachewasuptodateusingcachetosatisfyrequests=캐시가 최신 상태였습니다. 캐시를 사용하여 요청을 충족합니다.
Abouttoopenthezipfile=zip 파일을 열려고 합니다.
Cacheupdatedwithentries={0}개 항목으로 캐시가 업데이트되었습니다.
Processing={0} 처리 중
InTestTargetResourcedestexistsnotusingchecksumscontinuing=Test-TargetResource에 {0}이(가) 있지만 체크섬을 사용하지 않습니다. 계속 진행됩니다.
Notperformingchecksumthefileondiskhasthesamewritetimeasthelasttimeweverifieditscontents=체크섬을 수행하고 있지 않습니다. 디스크 파일의 쓰기 시간이 해당 내용을 마지막으로 확인했을 때와 같습니다.
destexistsandthehashmatcheseven={0}이(가) 있으며 LastModifiedTime이 일치하지 않아도 해시는 일치합니다. 캐시를 업데이트합니다.
InTestTargetResourcedestexistsandtheselectedtimestampChecksummatched=Test-TargetResource에 {0}이(가) 있으며 선택한 타임스탬프 {1}이(가) 일치합니다.
RemovePSDriveonRootpsdriveRoot=루트 {0}에서 PSDrive 제거
RemovingDir={0} 제거 중
Hashesofexistingandzipfilesmatchremoving=기존 및 zip 파일의 해시가 일치하여 제거됩니다.
HashdidnotmatchfilehasbeenmodifiedsinceitwasextractedLeaving=해시가 일치하지 않습니다. 추출된 후에 파일이 수정되었습니다. 그대로 유지합니다.
InSetTargetResourceexistsselectedtimestampmatched=Set-TargetResource에 {0}이(가) 있으며 선택한 타임스탬프 {1}이(가) 일치합니다. 제거됩니다.
InSetTargetResourceexistsdtheselectedtimestampnotmatchg=Set-TargetResource에 {0}이(가) 있으며 선택한 타임스탬프 {1}이(가) 일치하지 않습니다. 그대로 유지합니다.
existingappearstobeanemptydirectoryRemovingit={0}이(가) 빈 디렉터리인 것 같습니다. 제거됩니다.
LastWriteTimemtcheswhatwehaverecordnotreexaminingchecksum={0}의 LastWriteTime이 기록과 일치합니다. {1}을(를) 다시 검토하지 않습니다.
FoundfatdestwheregoingtoplaceoneandhashmatchedContinuing=파일을 배치하려던 {0}에서 파일을 찾았으며 해시가 일치합니다. 계속 진행됩니다.
FoundfileatdestwhereweweregoingtoplaceoneandhashdidntmatchItwillbeoverwritten=파일을 배치하려던 $dest에서 파일을 찾았으며 해시가 일치하지 않습니다. 파일을 덮어씁니다.
FoundfileatdestwhereweweregoingtoplaceoneanddoesnotmatchthesourcebutForcewasnotspecifiedErroring=파일을 배치하려던 {0}에서 파일을 찾았으며 원본과 일치하지 않지만 Force가 지정되지 않았습니다. 오류로 처리됩니다.
InSetTargetResourcedestexistsandtheselectedtimestamp$ChecksumdidnotmatchForcewasspecifiedwewilloverwrite="Set-TargetResource에 {0}이(가) 있으며 선택한 타임스탬프 {1}이(가) 일치하지 않습니다. Force가 지정되었습니다. 덮어씁니다.
FoundafileatdestandtimestampChecksumdoesnotmatchthesourcebutForcewasnotspecifiedErroring={0}에서 파일을 찾았으며 {1} 타임스탬프가 원본과 일치하지 않지만 Force가 지정되지 않았습니다. 오류로 처리됩니다.
FoundadirectoryatdestwhereafileshouldbeRemoving=파일이 있어야 하는 디렉터리를 {0}에서 찾았습니다. 제거됩니다.
FounddirectoryatdestwhereafileshouldbeandForcewasnotspecifiedErroring={0}에서 파일이 있어야 하는 디렉터리를 찾았으며 Force가 지정되지 않았습니다. 오류로 처리됩니다.
Writingtofiledest={0} 파일에 쓰는 중
RemovePSDriveonRootdriveRoot=루트 {0}에서 PSDrive 제거
Updatingcache=캐시 업데이트 중
FolderDirdoesnotexist={0} 폴더가 없습니다.
Examiningdirectorytoseeifitshouldberemoved={0}을(를) 검토하여 제거해야 하는지 확인하는 중
InSetTargetResourcedestexistsandtheselectedtimestampChecksummatchedwillleaveit=Set-TargetResource에 {0}이(가) 있으며 선택한 타임스탬프 {1}이(가) 일치합니다. 그대로 유지합니다.
###PSLOC

'@
