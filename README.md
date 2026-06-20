# FalseCrypt-desktop v1.0.0

project USAG: FalseCrypt desktop version

> FalseCrypt is E2EE storage filesystem and its client explorer

## CLI Usage

| Option | Input | Info | 정보 |
| :--- | :--- | :--- | :--- |

## GUI Usage

| function | Info | 정보 |
| :--- | :--- | :--- |

#### config

| Option | Type | Info | 정보 |
| :--- | :--- | :--- | :--- |

## Build Executable

This application uses Go programming language. [Install Go](https://go.dev/) to build yourself, or download pre-built release binary.
It takes few minutes to download and build GUI version. If you have different version of Go, remove `go.mod`, `go.sum` and retry.

windows cli
```bat
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o fc-lite.exe core.go lite.go
```

linux/mac cli
```bash
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o fc-lite core.go lite.go
```

windows gui
```bat
go mod init example.com
go mod tidy
go build -ldflags="-H windowsgui -s -w" -trimpath -o fc.exe core.go main.go pages.go
```

linux/mac gui
```bash
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o fc core.go main.go pages.go
```

fyne2 GUI requires C compiler and X11 environment. Selection dialog requires Zenity. check and install following packages before build.
```bash
gcc --version
sudo apt install zenity
sudo apt-get install pkg-config libgl1-mesa-dev libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev libxxf86vm-dev
```
