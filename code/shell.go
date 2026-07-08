// test826b : project USAG FalseCrypt-desktop
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Opsec"
	"github.com/taewook427/USAG-KOX/FalseCrypt"
	"github.com/taewook427/USAG-KOX/TP1"
)

// ===== progress logger =====
type Logger struct {
	Percent float64
	Data    []string
	lock    sync.RWMutex
}

func (l *Logger) AddLog(op string, msg string) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.Data = append(l.Data, fmt.Sprintf("[%s] [%s] %s", time.Now().Format("2006-01-02 15:04:05"), op, msg))
}

func (l *Logger) GetLog(del bool) string {
	l.lock.Lock()
	defer l.lock.Unlock()
	s := strings.Join(l.Data, "\n")
	if del {
		l.Data = nil
	}
	return s
}

func (l *Logger) SetPercent(p float64) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.Percent = max(min(p, 1), 0)
}

func (l *Logger) GetPercent() float64 {
	l.lock.RLock()
	defer l.lock.RUnlock()
	return l.Percent
}

// ===== process scheduler =====
type Scheduler struct {
	// filesystem
	IsUpdated bool
	fs        *FalseCrypt.PEVFS
	lock      sync.RWMutex
	Vio       FalseCrypt.VirtualIO

	// shell status
	Log        *Logger
	Cwd        *FalseCrypt.VFile
	CwdPath    []string
	NextUID    uint64
	IsReadonly bool
	IsWorking  atomic.Bool

	// user credentials
	Msg  string
	Salt []byte
	Hkey []byte // masked
	Mask *Bencrypt.Masker
}

// derive next uid
func (s *Scheduler) nextUID() {
	_, ok := s.fs.Meta[s.NextUID]
	for ok {
		s.NextUID++
		_, ok = s.fs.Meta[s.NextUID]
	}
}

// finish work
func (s *Scheduler) finish(op string) {
	if r := recover(); r == nil {
		s.Log.AddLog(op, "ok")
	} else {
		s.Log.AddLog(op, fmt.Sprintf("panic: %v", r))
	}
	s.IsWorking.Store(false)
}

// update edtime from root to cwd
func (s *Scheduler) chTime(cwd *FalseCrypt.VFile, cpath []string) {
	now := uint64(time.Now().Unix())
	rootUID := s.fs.Root.GetUID()
	if m, ok := s.fs.Meta[rootUID]; ok {
		m.EdTime = now
		s.fs.Meta[rootUID] = m
	}

	currNode := &s.fs.Root
	for i := 1; i < len(cpath); i++ {
		for j := range currNode.Children {
			child := &currNode.Children[j]
			if child.GetFlag(FalseCrypt.FLAG_DIR) {
				if m, ok := s.fs.Meta[child.GetUID()]; ok && m.Name == cpath[i] {
					m.EdTime = now
					s.fs.Meta[child.GetUID()] = m
					currNode = child
					break
				}
			}
		}
	}

	if cwd != &s.fs.Root {
		cwdUID := cwd.GetUID()
		if m, ok := s.fs.Meta[cwdUID]; ok {
			m.EdTime = now
			s.fs.Meta[cwdUID] = m
		}
	}
}

// import function assist
func (s *Scheduler) imAssist(localPath string, parent *FalseCrypt.VFile) error {
	// file info, UID, new child node
	fi, err := os.Stat(localPath)
	if err != nil {
		return err
	}

	s.lock.Lock()
	s.nextUID()
	uid := s.NextUID
	s.NextUID++
	s.lock.Unlock()

	var child FalseCrypt.VFile
	child.SetUID(uid)
	child.SetSL(FalseCrypt.SL_CONTROLLED)

	// import directory
	if fi.IsDir() {
		child.SetFlag(FalseCrypt.FLAG_DIR, true)

		s.lock.Lock()
		s.fs.Meta[uid] = FalseCrypt.VMeta{
			Name:   filepath.Base(localPath),
			EdTime: uint64(time.Now().Unix()),
		}
		s.lock.Unlock()

		// recursive calls
		entries, err := os.ReadDir(localPath)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := s.imAssist(filepath.Join(localPath, entry.Name()), &child); err != nil {
				return err
			}
		}

		// bind child
		s.lock.Lock()
		parent.Children = append(parent.Children, child)
		s.lock.Unlock()
		return nil
	}

	// import file
	size := fi.Size()
	meta := FalseCrypt.VMeta{
		Name:   filepath.Base(localPath),
		EdTime: uint64(time.Now().Unix()),
		Size:   uint64(size),
	}
	s.Log.AddLog("import", "working on: "+localPath)

	// optimize empty files
	if size == 0 {
		child.SetFlag(FalseCrypt.FLAG_EMPTY, true)
		meta.EncSize = 0

		s.lock.Lock()
		s.fs.Meta[uid] = meta
		parent.Children = append(parent.Children, child)
		s.lock.Unlock()
		return nil
	}

	// derive key and mask
	rawKey := Bencrypt.Random(int(FC_KEYSIZE))
	maskedKey, _ := s.Mask.XOR(rawKey)
	copy(meta.Key[:], maskedKey)

	// open temp file and make stream pipeline
	tmpPath := TP1.TempPath()
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath)
	}()

	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcmx1", rawKey); err != nil {
		return err
	}
	if size <= LIMIT_IMAGE { // compress then encrypt
		child.SetFlag(FalseCrypt.FLAG_COMPRESS, true)
		rawData, err := os.ReadFile(localPath)
		if err != nil {
			return err
		}
		compressedData := FalseCrypt.Compress(rawData)
		if err := sm.EnFile(bytes.NewReader(compressedData), int64(len(compressedData)), tmpFile); err != nil {
			return err
		}
	} else { // streaming encrypt
		srcFile, err := os.Open(localPath)
		if err != nil {
			return err
		}
		defer srcFile.Close()
		if err := sm.EnFile(srcFile, size, tmpFile); err != nil {
			return err
		}
	}

	// write padding, get total size
	currentOffset, err := tmpFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	padLen := Opsec.PadLen(currentOffset)
	if padLen > 0 {
		if err := Opsec.PadFile(tmpFile, padLen); err != nil {
			return err
		}
	}
	finalSize, err := tmpFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	meta.EncSize = uint64(currentOffset)
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// chunk upload
	chunkIdx := 0
	remainingEnc := finalSize
	s.Log.SetPercent(0)
	for remainingEnc > 0 {
		currentChunkSize := min(remainingEnc, CHUNKSIZE)
		chunkData := make([]byte, currentChunkSize)
		if _, err := io.ReadFull(tmpFile, chunkData); err != nil {
			return err
		}

		cid := s.fs.Account.GetCID(uid, uint32(chunkIdx))
		if err := s.Vio.WriteChunk(cid, chunkData); err != nil {
			return err
		}
		chunkIdx++
		remainingEnc -= currentChunkSize
		s.Log.SetPercent(float64(finalSize-remainingEnc) / float64(finalSize))
	}

	// bind child node
	s.lock.Lock()
	s.fs.Meta[uid] = meta
	parent.Children = append(parent.Children, child)
	s.lock.Unlock()
	return nil
}

// export function assist
func (s *Scheduler) exAssist(node *FalseCrypt.VFile, localDstDir string) error {
	// get metadata
	s.lock.RLock()
	uid := node.GetUID()
	meta, ok := s.fs.Meta[uid]
	s.lock.RUnlock()
	if !ok {
		return fmt.Errorf("metadata not found for UID %d", uid)
	}
	targetPath := filepath.Join(localDstDir, meta.Name)

	// export directory
	if node.GetFlag(FalseCrypt.FLAG_DIR) {
		if err := os.MkdirAll(targetPath, 0755); err != nil {
			return err
		}
		s.lock.Lock()
		children := slices.Clone(node.Children)
		s.lock.Unlock()
		for i := range children {
			if err := s.exAssist(&children[i], targetPath); err != nil {
				return err
			}
		}
		return nil
	}
	s.Log.AddLog("export", "working on: "+meta.Name) // export file

	// empty file optimization
	if node.GetFlag(FalseCrypt.FLAG_EMPTY) || meta.Size == 0 {
		f, err := os.Create(targetPath)
		if err != nil {
			return err
		}
		f.Close()
		return nil
	}

	// get file key
	s.lock.Lock()
	rawKey, err := s.Mask.XOR(meta.Key[0:FC_KEYSIZE])
	s.lock.Unlock()
	if err != nil {
		return err
	}
	defer sclear(rawKey)

	// download to tempfile
	tmpPath := TP1.TempPath()
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath)
	}()

	// download chunks
	chunkIdx := 0
	remainingEnc := int64(meta.EncSize)
	finalEncSize := int64(meta.EncSize)
	s.Log.SetPercent(0)
	for remainingEnc > 0 {
		cid := s.fs.Account.GetCID(uid, uint32(chunkIdx))
		chunkData, err := s.Vio.ReadChunk(cid)
		if err != nil {
			return err
		}

		if _, err := tmpFile.Write(chunkData); err != nil {
			return err
		}
		chunkIdx++
		remainingEnc -= int64(len(chunkData))
		if finalEncSize > 0 {
			progress := float64(finalEncSize-remainingEnc) / float64(finalEncSize)
			s.Log.SetPercent(progress)
		}
	}

	// decrypt file
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return err
	}
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcmx1", rawKey); err != nil {
		return err
	}

	if node.GetFlag(FalseCrypt.FLAG_COMPRESS) { // decrypt then decompress
		decBuf := new(bytes.Buffer)
		if err := sm.DeFile(tmpFile, int64(meta.EncSize), decBuf); err != nil {
			return err
		}
		decompressedData, err := FalseCrypt.Decompress(decBuf.Bytes())
		if err != nil {
			return err
		}
		if err := os.WriteFile(targetPath, decompressedData, 0644); err != nil {
			return err
		}
	} else { // streaming decrypt
		dstFile, err := os.Create(targetPath)
		if err != nil {
			return err
		}
		defer dstFile.Close()
		if err := sm.DeFile(tmpFile, int64(meta.EncSize), dstFile); err != nil {
			return err
		}
	}
	return nil
}

// cat function assist
func (s *Scheduler) catAssist(sel string) []byte {
	// find file node and metadata
	s.lock.RLock()
	cwd := s.Cwd
	var uid uint64
	var meta FalseCrypt.VMeta
	var isEmpty, isCmp bool
	found := false

	for i := range cwd.Children {
		child := &cwd.Children[i]
		if m, ok := s.fs.Meta[child.GetUID()]; ok && m.Name == sel {
			if !child.GetFlag(FalseCrypt.FLAG_DIR) {
				uid = child.GetUID()
				meta = m
				isEmpty = child.GetFlag(FalseCrypt.FLAG_EMPTY) || m.Size == 0
				isCmp = child.GetFlag(FalseCrypt.FLAG_COMPRESS)
				found = true
				break
			}
		}
	}
	s.lock.RUnlock()

	// empty file optimization, size check
	if !found {
		s.Log.AddLog("cat", "no file: "+sel)
		return nil
	}
	if isEmpty {
		return []byte{}
	}
	if meta.Size > uint64(LIMIT_IMAGE) || meta.EncSize > uint64(CHUNKSIZE) {
		s.Log.AddLog("cat", "file exceeds size limit")
		return nil
	}
	s.Log.AddLog("cat", "working on: "+meta.Name)
	s.Log.SetPercent(0)

	// read single chunk
	cid := s.fs.Account.GetCID(uid, 0)
	chunkData, err := s.Vio.ReadChunk(cid)
	if err != nil {
		s.Log.AddLog("cat", fmt.Sprintf("read chunk error: %v", err))
		return nil
	}
	s.Log.SetPercent(1.0)

	// decrypt with key
	s.lock.Lock()
	rawKey, err := s.Mask.XOR(meta.Key[0:FC_KEYSIZE])
	s.lock.Unlock()
	if err != nil {
		s.Log.AddLog("cat", fmt.Sprintf("key derivation error: %v", err))
		return nil
	}
	defer sclear(rawKey)

	// decrypt chunk
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcmx1", rawKey); err != nil {
		s.Log.AddLog("cat", fmt.Sprintf("crypto master init error: %v", err))
		return nil
	}
	decBuf := new(bytes.Buffer)
	if err := sm.DeFile(bytes.NewReader(chunkData), int64(meta.EncSize), decBuf); err != nil {
		s.Log.AddLog("cat", fmt.Sprintf("decrypt error: %v", err))
		return nil
	}

	// decompress
	if isCmp {
		decompressedData, err := FalseCrypt.Decompress(decBuf.Bytes())
		if err != nil {
			s.Log.AddLog("cat", fmt.Sprintf("decompress error: %v", err))
			return nil
		}
		return decompressedData
	}
	return decBuf.Bytes()
}

func (s *Scheduler) Init(fs *FalseCrypt.PEVFS, vio FalseCrypt.VirtualIO, msg string, salt []byte, hkey []byte) {
	// initialize fields
	s.IsUpdated = false
	s.fs = fs
	s.Vio = vio
	s.Log = new(Logger)
	s.Cwd = &s.fs.Root
	s.CwdPath = []string{s.fs.Meta[s.fs.Root.GetUID()].Name}
	s.IsReadonly = s.fs.Account.UserName != "root"
	s.IsWorking.Store(false)
	s.Msg = msg
	s.Salt = salt
	s.Mask = Bencrypt.GetMasker(-1)
	s.Hkey, _ = s.Mask.XOR(hkey)

	// derive next uid
	s.NextUID = 0
	s.nextUID()
}

// change working dir
func (s *Scheduler) Cd(path string, isSub bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if path == "" {
		return
	}

	// dir stack init
	var nodeStack []*FalseCrypt.VFile
	var pathStack []string
	if isSub {
		nodeStack = append(nodeStack, s.Cwd)
		pathStack = append(pathStack, s.CwdPath...)
	} else {
		nodeStack = append(nodeStack, &s.fs.Root)
		pathStack = append(pathStack, s.fs.Meta[s.fs.Root.GetUID()].Name)
	}

	// match by name
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		currNode := nodeStack[len(nodeStack)-1]
		found := false

		// find exact dir
		for i := range currNode.Children {
			child := &currNode.Children[i]
			if child.GetFlag(FalseCrypt.FLAG_DIR) {
				if meta, ok := s.fs.Meta[child.GetUID()]; ok && meta.Name == part {
					nodeStack = append(nodeStack, child)
					pathStack = append(pathStack, part)
					found = true
					break
				}
			}
		}
		if !found {
			s.Log.AddLog("cd", "no dir: "+path)
			return
		}
	}

	// update current dir
	s.Cwd = nodeStack[len(nodeStack)-1]
	s.CwdPath = pathStack
}

// list dir elements, (names, size, edtime, seclvl, isdir, userA, userB)
func (s *Scheduler) Ls() ([]string, []uint64, []uint64, []uint8, [][]bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	var names []string
	var sizes []uint64
	var edtimes []uint64
	var seclvls []uint8
	var flags [][]bool

	// get data of children
	for i := range s.Cwd.Children {
		child := &s.Cwd.Children[i]
		meta, ok := s.fs.Meta[child.GetUID()]
		if !ok {
			continue
		}
		names = append(names, meta.Name)
		sizes = append(sizes, meta.Size)
		edtimes = append(edtimes, meta.EdTime)
		seclvls = append(seclvls, child.GetSL())
		f := []bool{
			child.GetFlag(FalseCrypt.FLAG_DIR),
			child.GetFlag(FalseCrypt.FLAG_USER_A),
			child.GetFlag(FalseCrypt.FLAG_USER_B),
		}
		flags = append(flags, f)
	}

	// Create indices slice for sorting
	indices := make([]int, len(names))
	for i := range indices {
		indices[i] = i
	}

	// sort indices: dir first, then by name
	sort.Slice(indices, func(i, j int) bool {
		idxI := indices[i]
		idxJ := indices[j]

		isDirI := flags[idxI][0]
		isDirJ := flags[idxJ][0]
		if isDirI != isDirJ {
			return isDirI // directory first
		}
		nameI := strings.ToLower(names[idxI])
		nameJ := strings.ToLower(names[idxJ])
		if nameI == nameJ {
			return names[idxI] < names[idxJ]
		}
		return nameI < nameJ
	})

	// Rearrange slices based on sorted indices
	sortedNames := make([]string, len(names))
	sortedSizes := make([]uint64, len(sizes))
	sortedEdtimes := make([]uint64, len(edtimes))
	sortedSeclvls := make([]uint8, len(seclvls))
	sortedFlags := make([][]bool, len(flags))

	for i, idx := range indices {
		sortedNames[i] = names[idx]
		sortedSizes[i] = sizes[idx]
		sortedEdtimes[i] = edtimes[idx]
		sortedSeclvls[i] = seclvls[idx]
		sortedFlags[i] = flags[idx]
	}
	return sortedNames, sortedSizes, sortedEdtimes, sortedSeclvls, sortedFlags
}

// list dir debug info, (uid, key, size, esize, filenum, dirnum)
func (s *Scheduler) LsDbg(subnm string) (uint64, []byte, uint64, uint64, int, int) {
	s.IsWorking.Store(true)
	defer s.finish("lsdbg")
	s.lock.RLock()
	defer s.lock.RUnlock()
	target := s.Cwd

	// find sub node
	if subnm != "" {
		found := false
		for i := range s.Cwd.Children {
			child := &s.Cwd.Children[i]
			if m, ok := s.fs.Meta[child.GetUID()]; ok && m.Name == subnm {
				target = child
				found = true
				break
			}
		}
		if !found {
			s.Log.AddLog("lsdbg", "no file: "+subnm)
			return 0, nil, 0, 0, 0, 0
		}
	}

	// find recursively
	var filenum, dirnum int
	var totalSize, totalEsize uint64
	var walk func(node *FalseCrypt.VFile)
	walk = func(node *FalseCrypt.VFile) {
		if node.GetFlag(FalseCrypt.FLAG_DIR) {
			dirnum++
		} else {
			filenum++
			if meta, ok := s.fs.Meta[node.GetUID()]; ok {
				totalSize += meta.Size
				totalEsize += meta.EncSize
			}
		}
		for i := range node.Children {
			child := &node.Children[i]
			if child.GetFlag(FalseCrypt.FLAG_DIR) {
				walk(child)
			} else {
				filenum++
				if meta, ok := s.fs.Meta[child.GetUID()]; ok {
					totalSize += meta.Size
					totalEsize += meta.EncSize
				}
			}
		}
	}

	// return result
	walk(target)
	uid := target.GetUID()
	meta := s.fs.Meta[uid]
	key, _ := s.Mask.XOR(meta.Key[0:FC_KEYSIZE])
	return uid, key, totalSize, totalEsize, filenum, dirnum
}

// search files or dir
func (s *Scheduler) Search(pattern string, userA bool, userB bool, minsl uint8) []string {
	s.IsWorking.Store(true)
	defer s.finish("search")
	s.lock.RLock()
	defer s.lock.RUnlock()

	// compile regex
	var results []string
	re, err := regexp.Compile(pattern)
	if err != nil {
		s.Log.AddLog("search", "invalid pattern: "+err.Error())
		return nil
	}

	// recursive search
	var walk func(node *FalseCrypt.VFile, currentPath string)
	walk = func(node *FalseCrypt.VFile, currentPath string) {
		for i := range node.Children {
			child := &node.Children[i]
			meta, ok := s.fs.Meta[child.GetUID()]
			if !ok {
				continue
			}
			childPath := meta.Name
			if currentPath != "" {
				childPath = currentPath + "/" + meta.Name
			}

			// check conditions
			match := true
			if userA && !child.GetFlag(FalseCrypt.FLAG_USER_A) {
				match = false
			}
			if userB && !child.GetFlag(FalseCrypt.FLAG_USER_B) {
				match = false
			}
			if child.GetSL() < minsl {
				match = false
			}

			// serach pattern
			if match && re.MatchString(meta.Name) {
				results = append(results, childPath)
			}
			if child.GetFlag(FalseCrypt.FLAG_DIR) {
				walk(child, childPath)
			}
		}
	}

	walk(s.Cwd, "")
	return results
}

// import files or dir
func (s *Scheduler) Import(paths []string) {
	s.IsWorking.Store(true)
	defer s.finish("import")
	if s.IsReadonly {
		s.Log.AddLog("import", "readonly status")
		return
	}

	// import each path
	s.lock.RLock()
	cwd, cpath := s.Cwd, slices.Clone(s.CwdPath)
	s.lock.RUnlock()
	for _, p := range paths {
		if err := s.imAssist(p, cwd); err != nil {
			s.Log.AddLog("import", fmt.Sprintf("error %v with %s", err, p))
			return
		}
	}

	// update edtime metadata
	s.lock.Lock()
	defer s.lock.Unlock()
	s.chTime(cwd, cpath)
	s.IsUpdated = true
}

// export files or dir
func (s *Scheduler) Export(sels []string, dst string) {
	s.IsWorking.Store(true)
	defer s.finish("export")

	// copy targets
	s.lock.Lock()
	cwd := s.Cwd
	var targets []FalseCrypt.VFile
	for _, sel := range sels {
		if sel == "" {
			continue
		}
		for i := range cwd.Children {
			child := &cwd.Children[i]
			if meta, ok := s.fs.Meta[child.GetUID()]; ok && meta.Name == sel {
				targets = append(targets, *child)
				break
			}
		}
	}
	s.lock.Unlock()

	// export targets
	if len(targets) == 0 {
		s.Log.AddLog("export", "no matching targets found")
		return
	}
	for _, target := range targets {
		if err := s.exAssist(&target, dst); err != nil {
			s.Log.AddLog("export", fmt.Sprintf("error %v with %s", err, s.fs.Meta[target.GetUID()].Name))
			return
		}
	}
}

// view file content
func (s *Scheduler) Cat(sels []string) [][]byte {
	s.IsWorking.Store(true)
	defer s.finish("cat")

	var results [][]byte
	for _, sel := range sels {
		results = append(results, s.catAssist(sel))
	}
	return results
}

// remove files or dir
func (s *Scheduler) Rm(sels []string) {
	s.IsWorking.Store(true)
	defer s.finish("rm")
	if s.IsReadonly {
		s.Log.AddLog("rm", "readonly status")
		return
	}

	// assist for collectiong all UID
	targetSet := make(map[string]bool)
	for _, sel := range sels {
		targetSet[sel] = true
	}

	s.lock.Lock()
	var delUIDs []uint64
	var delNames []string
	var delEncSizes []uint64
	var delIsDirs []bool
	var delIsEmpties []bool

	var collect func(node *FalseCrypt.VFile)
	collect = func(node *FalseCrypt.VFile) {
		uid := node.GetUID()
		if meta, ok := s.fs.Meta[uid]; ok {
			delUIDs = append(delUIDs, uid)
			delNames = append(delNames, meta.Name)
			delEncSizes = append(delEncSizes, meta.EncSize)
			delIsDirs = append(delIsDirs, node.GetFlag(FalseCrypt.FLAG_DIR))
			delIsEmpties = append(delIsEmpties, node.GetFlag(FalseCrypt.FLAG_EMPTY))
		}
		for i := range node.Children {
			collect(&node.Children[i])
		}
	}

	// walk children, make new vfile array
	var newChildren []FalseCrypt.VFile
	foundAny := false
	for i := range s.Cwd.Children {
		child := &s.Cwd.Children[i]
		if meta, ok := s.fs.Meta[child.GetUID()]; ok && targetSet[meta.Name] {
			foundAny = true
			collect(child)
		} else {
			newChildren = append(newChildren, s.Cwd.Children[i])
		}
	}
	if !foundAny {
		s.Log.AddLog("rm", "no file or directory matched")
		s.lock.Unlock()
		return
	}

	// delete nodes and metas
	s.Cwd.Children = newChildren
	for _, uid := range delUIDs {
		delete(s.fs.Meta, uid)
	}
	s.IsUpdated = true
	s.chTime(s.Cwd, s.CwdPath)
	s.lock.Unlock()

	// delete chunks
	for i := range delUIDs {
		if delIsDirs[i] || delIsEmpties[i] || delEncSizes[i] == 0 {
			continue
		}
		s.Log.AddLog("rm", "deleting: "+delNames[i])
		finalSize := int64(delEncSizes[i]) + Opsec.PadLen(int64(delEncSizes[i]))
		remainingEnc := finalSize
		chunkIdx := 0

		for remainingEnc > 0 {
			currentChunkSize := min(remainingEnc, CHUNKSIZE)
			cid := s.fs.Account.GetCID(delUIDs[i], uint32(chunkIdx))
			if err := s.Vio.DelChunk(cid); err != nil {
				s.Log.AddLog("rm", fmt.Sprintf("delete chunk error for %s (chunk %d): %v", delNames[i], chunkIdx, err))
			}
			chunkIdx++
			remainingEnc -= currentChunkSize
		}
	}
}

// move files or dir
func (s *Scheduler) Mv(src string, sels []string) {
	if s.IsReadonly {
		s.Log.AddLog("mv", "readonly status")
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()

	// find src dir
	srcParts := []string{s.fs.Meta[s.fs.Root.GetUID()].Name}
	srcNode := &s.fs.Root
	parts := strings.Split(src, "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		found := false
		for i := range srcNode.Children {
			child := &srcNode.Children[i]
			if child.GetFlag(FalseCrypt.FLAG_DIR) {
				if meta, ok := s.fs.Meta[child.GetUID()]; ok && meta.Name == part {
					srcNode = child
					srcParts = append(srcParts, part)
					found = true
					break
				}
			}
		}
		if !found {
			s.Log.AddLog("mv", "source dir not found: "+src)
			return
		}
	}
	if !srcNode.GetFlag(FalseCrypt.FLAG_DIR) {
		s.Log.AddLog("mv", "source is not a directory: "+src)
		return
	}

	// check same dir
	if srcNode.GetUID() == s.Cwd.GetUID() {
		s.Log.AddLog("mv", "source and destination are the same")
		return
	}

	movedCount := 0
	for _, sel := range sels {
		if sel == "" {
			continue
		}
		idx := -1
		for i := range srcNode.Children {
			child := &srcNode.Children[i]
			if meta, ok := s.fs.Meta[child.GetUID()]; ok && meta.Name == sel {
				idx = i
				break
			}
		}
		if idx == -1 {
			s.Log.AddLog("mv", "target not found in source: "+sel)
			continue
		}
		target := srcNode.Children[idx]

		// check move validity
		targetParts := append(slices.Clone(srcParts), sel)
		if target.GetFlag(FalseCrypt.FLAG_DIR) {
			isInvalidMove := false
			if len(s.CwdPath) >= len(targetParts) {
				isInvalidMove = true
				for i := 0; i < len(targetParts); i++ {
					if s.CwdPath[i] != targetParts[i] {
						isInvalidMove = false
						break
					}
				}
			}
			if isInvalidMove {
				s.Log.AddLog("mv", "cannot move parent to child: "+sel)
				continue
			}
		}

		// check name duplication
		duplicate := false
		for i := range s.Cwd.Children {
			if m, ok := s.fs.Meta[s.Cwd.Children[i].GetUID()]; ok && m.Name == sel {
				duplicate = true
				break
			}
		}
		if duplicate {
			s.Log.AddLog("mv", "duplicate name in destination: "+sel)
			continue
		}

		// move node
		srcNode.Children = append(srcNode.Children[:idx], srcNode.Children[idx+1:]...)
		s.Cwd.Children = append(s.Cwd.Children, target)
		movedCount++
	}
	if movedCount > 0 {
		s.IsUpdated = true
		s.chTime(s.Cwd, s.CwdPath)
	}
}

// rename files or dir
func (s *Scheduler) Rename(sel string, nm string) {
	if s.IsReadonly {
		s.Log.AddLog("rename", "readonly status")
		return
	}
	if nm == "" || strings.Contains(nm, "/") {
		s.Log.AddLog("rename", "invalid new name: "+nm)
		return
	}

	// check name duplication
	s.lock.Lock()
	defer s.lock.Unlock()
	for i := range s.Cwd.Children {
		if m, ok := s.fs.Meta[s.Cwd.Children[i].GetUID()]; ok && m.Name == nm {
			s.Log.AddLog("rename", "duplicate name: "+nm)
			return
		}
	}

	// rename node
	found := false
	for i := range s.Cwd.Children {
		child := &s.Cwd.Children[i]
		if m, ok := s.fs.Meta[child.GetUID()]; ok && m.Name == sel {
			uid := child.GetUID()
			meta := s.fs.Meta[uid]
			meta.Name = nm
			s.fs.Meta[uid] = meta
			found = true
			break
		}
	}
	if !found {
		s.Log.AddLog("rename", "target not found: "+sel)
		return
	}
	s.IsUpdated = true
	s.chTime(s.Cwd, s.CwdPath)
}

// change file mode
func (s *Scheduler) Chmod(sel string, userA bool, userB bool, seclvl uint8, recur bool) {
	if s.IsReadonly {
		s.Log.AddLog("chmod", "readonly status")
		return
	}
	if sel == "" {
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()

	// change node mode
	var changeMode func(node *FalseCrypt.VFile)
	changeMode = func(node *FalseCrypt.VFile) {
		node.SetFlag(FalseCrypt.FLAG_USER_A, userA)
		node.SetFlag(FalseCrypt.FLAG_USER_B, userB)
		node.SetSL(seclvl)
		if recur {
			for i := range node.Children {
				changeMode(&node.Children[i])
			}
		}
	}

	// find target
	found := false
	for i := range s.Cwd.Children {
		child := &s.Cwd.Children[i]
		if m, ok := s.fs.Meta[child.GetUID()]; ok && m.Name == sel {
			changeMode(child)
			found = true
			break
		}
	}
	if found {
		s.IsUpdated = true
		s.chTime(s.Cwd, s.CwdPath)
	} else {
		s.Log.AddLog("chmod", "target not found: "+sel)
	}
}

// make new dir
func (s *Scheduler) Mkdir(nm string) {
	if s.IsReadonly {
		s.Log.AddLog("mkdir", "readonly status")
		return
	}
	if nm == "" || strings.Contains(nm, "/") {
		s.Log.AddLog("mkdir", "invalid name: "+nm)
		return
	}

	// check name duplication
	s.lock.Lock()
	defer s.lock.Unlock()
	for i := range s.Cwd.Children {
		if m, ok := s.fs.Meta[s.Cwd.Children[i].GetUID()]; ok && m.Name == nm {
			s.Log.AddLog("mkdir", "duplicate name: "+nm)
			return
		}
	}

	// derive unique uid
	s.nextUID()
	uid := s.NextUID
	s.NextUID++

	// make new node
	var child FalseCrypt.VFile
	child.SetUID(uid)
	child.SetSL(FalseCrypt.SL_CONTROLLED)
	child.SetFlag(FalseCrypt.FLAG_DIR, true)
	s.fs.Meta[uid] = FalseCrypt.VMeta{
		Name:   nm,
		EdTime: uint64(time.Now().Unix()),
	}
	s.Cwd.Children = append(s.Cwd.Children, child)
	s.IsUpdated = true
	s.chTime(s.Cwd, s.CwdPath)
}

// change user flag
func (s *Scheduler) Chflag(userA string, userB string) {
	if userA == "" || userB == "" {
		s.Log.AddLog("chflag", "invalid user flag")
		return
	}
	if s.IsReadonly {
		s.Log.AddLog("chflag", "readonly status")
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.fs.Account.UserBitA = userA
	s.fs.Account.UserBitB = userB
	s.IsUpdated = true
	s.Log.AddLog("chflag", "user flag updated")
}

// commit filesystem to storage
func (s *Scheduler) Commit() {
	s.IsWorking.Store(true)
	defer s.finish("commit")
	if s.IsReadonly {
		s.Log.AddLog("commit", "readonly status")
		return
	}

	// restore hkey
	s.lock.Lock()
	hkey, err := s.Mask.XOR(s.Hkey)
	if err != nil {
		s.lock.Unlock()
		s.Log.AddLog("commit", fmt.Sprintf("key unmask error: %v", err))
		return
	}
	defer sclear(hkey)

	// pack PEVFS
	buf := new(bytes.Buffer)
	err = s.fs.Pack(hkey, s.Salt, s.Msg, buf)
	s.lock.Unlock()
	if err != nil {
		s.Log.AddLog("commit", fmt.Sprintf("pack error: %v", err))
		return
	}

	// push account file
	if err := s.Vio.SetAccount(s.fs.Account.UserName, bytes.NewReader(buf.Bytes()), int64(buf.Len())); err != nil {
		s.Log.AddLog("commit", fmt.Sprintf("storage save error: %v", err))
		return
	}
	s.lock.Lock()
	s.IsUpdated = false
	s.lock.Unlock()

	// 10% trim empty
	if time.Now().Unix()%10 == 0 {
		if err := s.Vio.TrimEmpty(); err == nil {
			s.Log.AddLog("commit", "empty dir trimmed")
		} else {
			s.Log.AddLog("commit", fmt.Sprintf("trim empty error on storage: %v", err))
		}
	}
}

// change password
func (s *Scheduler) Passwd(msg string, pw []byte, kf []byte, newWrkey []byte) {
	s.IsWorking.Store(true)
	defer s.finish("passwd")

	// make new salt, hkey
	salt := Bencrypt.Random(32)
	hkey, err := MkHkey(salt, pw, kf)
	if err != nil {
		s.Log.AddLog("passwd", fmt.Sprintf("key derivation error: %v", err))
		return
	}
	defer sclear(hkey)

	// update write auth key if provided
	s.lock.Lock()
	if len(newWrkey) > 0 {
		s.fs.Account.WriteAuth = newWrkey
		s.Vio, err = Config.GetIO(newWrkey)
		if err != nil {
			s.Log.AddLog("passwd", fmt.Sprintf("IO init error: %v", err))
			return
		}
	}
	s.lock.Unlock()

	// make buffer, pack
	s.lock.Lock()
	buf := new(bytes.Buffer)
	err = s.fs.Pack(hkey, salt, msg, buf)
	s.lock.Unlock()
	if err != nil {
		s.Log.AddLog("passwd", fmt.Sprintf("pack error: %v", err))
		return
	}

	// push account file
	if s.IsReadonly {
		filename := hex.EncodeToString([]byte(s.fs.Account.UserName)) + ".webp"
		err = os.WriteFile(filename, buf.Bytes(), 0644)
		if err != nil {
			s.Log.AddLog("passwd", fmt.Sprintf("local write error: %v", err))
			return
		}
		s.Log.AddLog("passwd", "accfile saved as: "+filename)
	} else {
		err = s.Vio.SetAccount(s.fs.Account.UserName, bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			s.Log.AddLog("passwd", fmt.Sprintf("storage save error: %v", err))
			return
		}
	}

	// update credentials
	s.lock.Lock()
	s.IsUpdated = false // packed
	s.Msg = msg
	s.Salt = salt
	maskedHkey, _ := s.Mask.XOR(hkey)
	sclear(s.Hkey)
	s.Hkey = maskedHkey
	s.lock.Unlock()
}

// share current dir with limited account
func (s *Scheduler) Share(username string, seclvl uint8, msg string, pw []byte, kf []byte) {
	s.IsWorking.Store(true)
	defer s.finish("share")
	if username == "" || username == "root" || username == s.fs.Account.UserName {
		s.Log.AddLog("share", "invalid username: "+username)
		return
	}

	// make new salt, hkey
	salt := Bencrypt.Random(32)
	hkey, err := MkHkey(salt, pw, kf)
	if err != nil {
		s.Log.AddLog("share", fmt.Sprintf("key derivation error: %v", err))
		return
	}
	defer sclear(hkey)

	// make new PEVFS
	s.lock.Lock()
	vu := FalseCrypt.VUser{
		StorageName: s.fs.Account.StorageName,
		UserName:    username,
		SecureLevel: seclvl,
		UserBitA:    s.fs.Account.UserBitA,
		UserBitB:    s.fs.Account.UserBitB,
		CIDpad:      slices.Clone(s.fs.Account.CIDpad),
		CIDkey:      slices.Clone(s.fs.Account.CIDkey),
		WriteAuth:   nil, // no write auth
	}
	newPevfs := new(FalseCrypt.PEVFS)
	newPevfs.Init(vu, *s.Cwd, s.fs.Meta, seclvl, FC_KEYSIZE)

	// pack PEVFS
	buf := new(bytes.Buffer)
	err = newPevfs.Pack(hkey, salt, msg, buf)
	s.lock.Unlock()
	if err != nil {
		s.Log.AddLog("share", fmt.Sprintf("pack error: %v", err))
		return
	}

	// push account file
	if s.IsReadonly {
		filename := hex.EncodeToString([]byte(username)) + ".webp"
		err = os.WriteFile(filename, buf.Bytes(), 0644)
		if err != nil {
			s.Log.AddLog("share", fmt.Sprintf("local write error: %v", err))
			return
		}
		s.Log.AddLog("share", "accfile saved as: "+filename)
	} else {
		err = s.Vio.SetAccount(username, bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			s.Log.AddLog("share", fmt.Sprintf("storage save error: %v", err))
			return
		}
	}
}

// sync with remote storage
func (s *Scheduler) Sync() {
	s.IsWorking.Store(true)
	defer s.finish("sync")
	if s.IsReadonly {
		s.Log.AddLog("sync", "readonly status")
		return
	}

	// get remote storage bloom filter
	s.Log.AddLog("sync", "requesting remote storage bloom filter")
	remoteBfBytes := s.Vio.CheckChunk()
	if len(remoteBfBytes) == 0 {
		s.Log.AddLog("sync", "failed to fetch bloom filter")
		return
	}
	var bfRemote FalseCrypt.BloomFilter
	if err := bfRemote.Import(remoteBfBytes); err != nil {
		s.Log.AddLog("sync", fmt.Sprintf("failed to import bloom filter: %v", err))
		return
	}

	// collect uid and encsize
	s.lock.RLock()
	var uids []uint64
	var encSizes []uint64
	for uid, meta := range s.fs.Meta {
		if meta.EncSize > 0 {
			uids = append(uids, uid)
			encSizes = append(encSizes, meta.EncSize)
		}
	}
	s.lock.RUnlock()

	// calculate total chunks
	var totalChunks uint64 = 0
	var fileChunkCounts []int
	for _, encSize := range encSizes {
		finalSize := int64(encSize) + Opsec.PadLen(int64(encSize))
		chunkCount := int((finalSize + CHUNKSIZE - 1) / CHUNKSIZE)
		if chunkCount == 0 && finalSize > 0 {
			chunkCount = 1
		}
		fileChunkCounts = append(fileChunkCounts, chunkCount)
		totalChunks += uint64(chunkCount)
	}
	if totalChunks == 0 {
		totalChunks = 1
	}

	// make return bloom filter
	var bfReturn FalseCrypt.BloomFilter
	bfReturn.Init(totalChunks, 0.001)
	s.Log.AddLog("sync", "walking through chunks to verify existence")
	missingChunks := 0
	for i, uid := range uids {
		count := fileChunkCounts[i]
		for chunkIdx := 0; chunkIdx < count; chunkIdx++ {
			cid := s.fs.Account.GetCID(uid, uint32(chunkIdx))
			if !bfRemote.Test(cid) {
				s.Log.AddLog("sync", fmt.Sprintf("chunk %d.%d is missing from remote storage (CID %x)", uid, chunkIdx, cid))
				missingChunks++
			}
			bfReturn.Add(cid)
		}
	}

	// log validity and return bloom filter
	if missingChunks > 0 {
		s.Log.AddLog("sync", fmt.Sprintf("warning: %d chunks are missing on remote storage", missingChunks))
	} else {
		s.Log.AddLog("sync", "all active chunks successfully verified in remote storage")
	}
	s.Log.AddLog("sync", "transmitting return bloom filter")
	if err := s.Vio.TrimChunk(bfReturn.Export()); err != nil {
		s.Log.AddLog("sync", fmt.Sprintf("failed to transmit return bloom filter: %v", err))
		return
	}
}
