// test826a : project USAG FalseCrypt-desktop
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/taewook427/USAG-KOX/BaseUI"
	"github.com/taewook427/USAG-KOX/FalseCrypt"
	"github.com/taewook427/USAG-KOX/TP1"
)

// ===== global variables =====
const FC_VERSION string = "2026 @k-atusa [USAG] FalseCrypt v1.0.1"
const FC_KEYSIZE uint8 = 32
const CHUNKSIZE int64 = 64 * 1048576
const LIMIT_IMAGE int64 = 16 * 1048576

var SCLEAR_BACK = func(b []byte) { clear(b) }

func sclear(data []byte) { SCLEAR_BACK(data); runtime.KeepAlive(data) }

var Config U1Config

// ===== config load, account fetch =====
type U1Config struct {
	AutoExpire int     `json:"expire"`
	Size       float32 `json:"size"`
	IsLocal    bool    `json:"islocal"`
	ServerURL  string  `json:"server"`
	LocalMeta  string  `json:"localmeta"`
}

func (c *U1Config) Load() error {
	data, err := os.ReadFile(filepath.Join(TP1.GetPath(), "config.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			Config.AutoExpire = 20
			Config.Size = 1.0
			Config.IsLocal = false
			Config.ServerURL = "http://127.0.0.1:80"
			Config.LocalMeta = "./chunkmeta.json"
			return c.Store()
		}
		return err
	}
	err = json.Unmarshal(data, c)
	BaseUI.FyneSize = c.Size
	return err
}

func (c *U1Config) Store() error {
	// store local meta
	_, err := os.Stat(Config.LocalMeta)
	if os.IsNotExist(err) {
		var meta FalseCrypt.ChunkMeta
		meta.MainPath = "./accounts"
		meta.BfSize = 1048576
		meta.Paths = []string{"./chunks"}
		meta.Caps = []int64{1024 * 1048576}
		meta.Weights = []float32{1.0}
		meta.WriteKey = Bencrypt.Random(32)
		ms, _ := meta.Save()
		os.WriteFile(Config.LocalMeta, []byte(ms), 0644)
	} else if err != nil {
		return err
	}

	// store config
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(TP1.GetPath(), "config.json"), data, 0644)
}

func (c *U1Config) GetIO(wrkey []byte) (FalseCrypt.VirtualIO, error) {
	if c.IsLocal {
		js, err := os.ReadFile(c.LocalMeta)
		if err != nil {
			return nil, err
		}
		meta := new(FalseCrypt.ChunkMeta)
		if err := meta.Init(string(js)); err != nil {
			return nil, err
		}
		io := new(FalseCrypt.ChunkBalancer)
		io.Init(meta)
		return io, nil
	} else {
		io := new(ClientIO)
		io.Init(c.ServerURL, wrkey)
		return io, nil
	}
}

// ===== core helpers =====
func MkHkey(salt []byte, pw []byte, kf []byte) ([]byte, error) {
	var hm Bencrypt.HashMaster
	if err := hm.Init("arg2st", -1, -1); err != nil {
		return nil, err
	}
	buf := make([]byte, len(pw)+len(kf))
	copy(buf, pw)
	copy(buf[len(pw):], kf)
	defer sclear(buf)
	_, hkey, err := hm.KDF(buf, salt)
	return hkey, err
}

func MakeAccFile(storage string, msg string, pw []byte, kf []byte, vio FalseCrypt.VirtualIO, wrkey []byte) error {
	// make vuser
	vu := FalseCrypt.VUser{
		StorageName: storage,
		UserName:    "root",
		SecureLevel: FalseCrypt.SL_TOPSECRET,
		UserBitA:    "UserA",
		UserBitB:    "UserB",
		CIDpad:      Bencrypt.Random(6),
		CIDkey:      Bencrypt.Random(32),
		WriteAuth:   wrkey,
	}

	// make vfile
	var vroot FalseCrypt.VFile
	vroot.SetUID(0)
	vroot.SetSL(FalseCrypt.SL_CONTROLLED)
	vroot.SetFlag(FalseCrypt.FLAG_DIR, true)

	// make vmeta
	vm := make(map[uint64]FalseCrypt.VMeta)
	vm[0] = FalseCrypt.VMeta{
		Name:   "",
		EdTime: uint64(time.Now().Unix()),
	}

	// make pevfs, push to storage
	pevfs := new(FalseCrypt.PEVFS)
	pevfs.Init(vu, vroot, vm, FalseCrypt.SL_TOPSECRET, FC_KEYSIZE)
	salt := Bencrypt.Random(32)
	hkey, err := MkHkey(salt, pw, kf)
	if err == nil {
		defer sclear(hkey)
	} else {
		return err
	}
	buf := new(bytes.Buffer)
	if err := pevfs.Pack(hkey, salt, msg, buf); err != nil {
		return err
	}
	return vio.SetAccount("root", bytes.NewBuffer(buf.Bytes()), int64(buf.Len()))
}

func GetAccFile(vio FalseCrypt.VirtualIO, username string) (string, string, []byte, error) {
	// download account file
	tmp := TP1.TempPath()
	f, err := os.Create(tmp)
	if err == nil {
		defer f.Close()
	} else {
		return tmp, "", nil, err
	}
	err = vio.GetAccount(username, f)
	if err != nil {
		return tmp, "", nil, err
	}

	// view account file
	f.Seek(0, 0)
	pevfs := new(FalseCrypt.PEVFS)
	msg, salt, err := pevfs.View(f)
	return tmp, msg, salt, err
}

func LoginAccFile(filepath string, pw []byte, kf []byte) (*FalseCrypt.PEVFS, []byte, error) {
	// open account file
	f, err := os.Open(filepath)
	if err == nil {
		defer f.Close()
	} else {
		return nil, nil, err
	}

	// view account file
	pevfs := new(FalseCrypt.PEVFS)
	pevfs.Init(FalseCrypt.VUser{}, FalseCrypt.VFile{}, nil, FalseCrypt.SL_TOPSECRET, FC_KEYSIZE)
	_, salt, err := pevfs.View(f)
	if err != nil {
		return nil, nil, err
	}

	// derive hkey and unlock account
	f.Seek(0, 0)
	hkey, err := MkHkey(salt, pw, kf)
	if err != nil {
		return nil, nil, err
	}
	if err = pevfs.Unpack(hkey, f); err != nil {
		sclear(hkey)
		return nil, nil, err
	}
	return pevfs, hkey, nil
}
