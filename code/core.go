// test826a : project USAG FalseCrypt-desktop
package main

import (
	"runtime"
	"sync"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/taewook427/USAG-KOX/FalseCrypt"
)

var SCLEAR_BACK = func(b []byte) { clear(b) }

func sclear(data []byte) { SCLEAR_BACK(data); runtime.KeepAlive(data) }

// progress logger
type Logger struct {
	Percent float64
	Data    []string
	lock    sync.RWMutex
}

// process scheduler
type Scheduler struct {
	// filesystem
	IsUpdated bool
	fs        *FalseCrypt.PEVFS
	io        FalseCrypt.VirtualIO
	lock      sync.RWMutex

	// shell status
	Log        *Logger
	Cwd        *FalseCrypt.VFile
	CwdPath    []string
	NextUID    uint64
	IsReadonly bool
	IsWorking  bool

	// user credentials
	Msg  string
	Salt []byte
	Hkey []byte // masked
	Mask *Bencrypt.Masker
}

/*
정보: 위치 크기들 개수들 시간
동작: 파일폴더추가 내보내기 보기 삭제 이동 이름바꾸기 권한바꾸기 새폴더
계정: 비번바꾸기 부분공유 청크동기화
*/
