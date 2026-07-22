# FalseCrypt-desktop v1.0.1

project USAG: FalseCrypt desktop version

> FalseCrypt is E2EE storage filesystem and its client explorer

## Usage

| function | Info | 정보 |
| :--- | :--- | :--- |
| Import | Imports files and folders into the storage. | 파일과 폴더를 저장소로 가져옵니다. |
| Export | Exports files and folders from the storage. | 파일과 폴더를 저장소에서 내보냅니다. |
| Mkdir | Creates a new folder. | 새 폴더를 생성합니다. |
| Rename | Renames files and folders. | 파일과 폴더의 이름을 변경합니다. |
| Delete | Deletes files and folders. | 파일과 폴더를 삭제합니다. |
| Move | Moves files and folders to another location. | 파일과 폴더의 위치를 이동합니다. |
| Chmod | Changes the security levels and attributes of files and folders. | 파일과 폴더의 보안레벨과 속성을 변경합니다. |
| View | Views the contents of small files in-memory. | 작은 파일의 내용을 인 메모리로 확인합니다. |
| Commit | Commits changes to the storage. | 저장소에 변경사항을 기록합니다. |
| Sync | Synchronizes the storage with chunk existence. | 저장소와 청크 존재성을 동기화합니다. |
| Share | Shares a part of the storage as read-only. | 저장소의 일부를 읽기전용으로 공유합니다. |
| Flags | Changes the user flag settings. | 사용자 플래그 설정을 변경합니다. |

#### config

| Option | Type | Info | 정보 |
| :--- | :--- | :--- | :--- |
| expire | int | Auto expire time in minutes. (Set 0 to disable auto expire) | 자동 세션 만료 시간. (0으로 설정 시 비활성화) |
| size | float | Fyne UI Scaling factor | Fyne UI 배율 |
| islocal | bool | Use local chunk storage (no server) | 로컬 청크 저장소 사용 (서버 없음) |
| server | string | Server URL for cloud storage | 클라우드 스토리지용 서버 URL |
| localmeta | string | Local chunk metadata file path | 로컬 청크 메타데이터 파일 경로 |

## Build Executable

This application uses Go programming language. [Install Go](https://go.dev/) to build yourself, or download pre-built release binary.
It takes few minutes to download and build GUI version. If you have different version of Go, remove `go.mod`, `go.sum` and retry.

windows
```bat
go mod init example.com
go mod tidy
go build -ldflags="-H windowsgui -s -w" -trimpath -o fc.exe core.go shell.go io.go ui.go
```

linux/mac
```bash
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o fc core.go shell.go io.go ui.go
```

fyne2 GUI requires C compiler and X11 environment. Selection dialog requires Zenity. check and install following packages before build.
```bash
gcc --version
sudo apt install zenity
sudo apt-get install pkg-config libgl1-mesa-dev libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev libxxf86vm-dev
```
