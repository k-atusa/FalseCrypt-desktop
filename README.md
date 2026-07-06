# FalseCrypt-desktop v1.0.0

project USAG: FalseCrypt desktop version

> FalseCrypt is E2EE storage filesystem and its client explorer

## Usage

| function | Info | 정보 |
| :--- | :--- | :--- |

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
