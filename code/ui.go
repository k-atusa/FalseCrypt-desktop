// test826d : project USAG FalseCrypt-desktop
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/k-atusa/USAG-Lib/Bencode"
	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/taewook427/USAG-KOX/BaseUI"
	"github.com/taewook427/USAG-KOX/FalseCrypt"
	"github.com/taewook427/USAG-KOX/MemView"
)

// ===== helpers =====
func formatSize(b uint64) string {
	switch {
	case b >= 1073741824:
		return fmt.Sprintf("%.2f GiB", float64(b)/1073741824)
	case b >= 1048576:
		return fmt.Sprintf("%.2f MiB", float64(b)/1048576)
	case b >= 1024:
		return fmt.Sprintf("%.2f KiB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func formatTime(ts uint64) string {
	if ts == 0 {
		return "-"
	}
	return time.Unix(int64(ts), 0).Format("2006-01-02 15:04")
}

func slName(sl uint8, isLong bool) string {
	nm := []string{"CT", "CF", "S", "TS", "CONTROLLED", "CONFIDENTIAL", "SECRET", "TOP SECRET"}
	if isLong {
		return nm[sl+4]
	}
	return nm[sl]
}

func wrapName(name string, maxWidth int) string {
	const maxLines = 3
	var lines []string
	var cur []rune
	var w int
	runes := []rune(name)
	overflow := false
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		var rw int
		if r < 128 {
			rw = 1
		} else {
			rw = 2
		}
		if w+rw > maxWidth && w > 0 {
			lines = append(lines, string(cur))
			if len(lines) >= maxLines {
				overflow = true
				break
			}
			cur = nil
			w = 0
		}
		cur = append(cur, r)
		w += rw
	}
	if !overflow && len(cur) > 0 {
		lines = append(lines, string(cur))
	}
	// truncate last line if overflow
	if overflow && len(lines) > 0 {
		last := []rune(lines[len(lines)-1])
		if len(last) > 2 {
			last = last[:len(last)-2]
		} else {
			last = nil
		}
		lines[len(lines)-1] = string(last) + "..."
	}
	return strings.Join(lines, "\n")
}

func slColor(sl uint8) color.NRGBA {
	switch sl {
	case FalseCrypt.SL_TOPSECRET:
		return color.NRGBA{R: 255, G: 80, B: 80, A: 255} // red
	case FalseCrypt.SL_SECRET:
		return color.NRGBA{R: 255, G: 165, B: 30, A: 255} // orange
	case FalseCrypt.SL_CONFIDENTIAL:
		return color.NRGBA{R: 100, G: 220, B: 100, A: 255} // green
	default:
		return color.NRGBA{R: 100, G: 100, B: 100, A: 255} // gray
	}
}

func parseSL(s string) uint8 {
	switch strings.ToUpper(s) {
	case "TOP SECRET", "TOPSECRET", "TS":
		return FalseCrypt.SL_TOPSECRET
	case "SECRET", "S":
		return FalseCrypt.SL_SECRET
	case "CONFIDENTIAL", "CF":
		return FalseCrypt.SL_CONFIDENTIAL
	default:
		return FalseCrypt.SL_CONTROLLED
	}
}

func getFileIcon(name string, isDir bool) fyne.Resource {
	var res fyne.Resource
	if isDir {
		res = theme.FolderOpenIcon()
	} else {
		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".txt", ".md", ".csv", ".json", ".pdf", ".pptx", ".docx", ".xlsx", ".hwp", ".hwpx":
			res = theme.DocumentIcon()
		case ".bat", ".c", ".cpp", ".cs", ".css", ".go", ".h", ".html", ".java", ".js", ".kt", ".lua", ".py", ".r", ".rb", ".rs", ".sh", ".ts":
			res = theme.FileTextIcon()
		case ".exe", ".dll", ".msi", ".lib", ".apk", ".jar":
			res = theme.FileApplicationIcon()
		case ".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".ico":
			res = theme.FileImageIcon()
		case ".mp3", ".wav", ".ogg", ".flac", ".m4a":
			res = theme.FileAudioIcon()
		case ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".webm":
			res = theme.FileVideoIcon()
		case ".zip", ".tar", ".rar", ".7z", ".gz", ".bz2", ".zst":
			res = theme.StorageIcon()
		default:
			res = theme.FileIcon()
		}
	}
	return theme.NewPrimaryThemedResource(res)
}

// ===== file card widget =====
type fileCard struct {
	widget.BaseWidget
	bg       *canvas.Rectangle
	content  fyne.CanvasObject
	onTap    func()
	onDblTap func()
	lastTap  time.Time
}

func (c *fileCard) Init(bg *canvas.Rectangle, content fyne.CanvasObject, onTap func(), onDblTap func()) {
	c.bg = bg
	c.content = content
	c.onTap = onTap
	c.onDblTap = onDblTap
}

func (c *fileCard) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(container.NewStack(c.bg, container.NewPadded(c.content)))
}

func (c *fileCard) Tapped(_ *fyne.PointEvent) {
	now := time.Now()
	if now.Sub(c.lastTap) < 450*time.Millisecond && c.onDblTap != nil {
		c.onDblTap()
	} else if c.onTap != nil {
		c.onTap()
	}
	c.lastTap = now
}

// ===== login page =====
type LoginPage struct {
	App    fyne.App
	Window fyne.Window
	mask   *Bencrypt.Masker

	// login state
	tmpPath string
	msg     string
	salt    []byte
	fetched bool

	kf []byte // masked
}

func (l *LoginPage) Main() {
	l.mask = Bencrypt.GetMasker(-1)
	l.App = app.New()
	l.App.Settings().SetTheme(&BaseUI.U1Theme{})
	l.Window = l.App.NewWindow("FalseCrypt")
	l.Fill()
	l.Window.Resize(fyne.NewSize(720*BaseUI.FyneSize, 480*BaseUI.FyneSize))
	l.Window.CenterOnScreen()

	// auto remove tempfile
	l.Window.SetCloseIntercept(func() {
		if l.tmpPath != "" {
			os.Remove(l.tmpPath)
		}
		l.Window.Close()
	})
	l.Window.ShowAndRun()
}

func (l *LoginPage) Fill() {
	// part0: username input
	ent0 := widget.NewEntry()
	ent0.SetPlaceHolder("Username (root)")
	lbl0 := widget.NewLabel("Msg:")
	lbl0.Wrapping = fyne.TextWrapWord
	btn0 := widget.NewButtonWithIcon("Search", theme.SearchIcon(), func() {
		username := ent0.Text
		if username == "" {
			username = "root"
		}
		go func() {
			tempVio, err := Config.GetIO(nil)
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, l.Window) })
				return
			}
			if l.tmpPath != "" {
				os.Remove(l.tmpPath)
			}
			tmpPath, msg, salt, err := GetAccFile(tempVio, username)
			if err != nil {
				os.Remove(tmpPath)
				fyne.Do(func() { dialog.ShowError(err, l.Window) })
				return
			}
			l.tmpPath = tmpPath
			l.msg = msg
			l.salt = salt
			l.fetched = true
			fyne.Do(func() { lbl0.SetText("Msg: " + msg) })
		}()
	})

	// part1: pwkf input
	ent1a := widget.NewPasswordEntry()
	ent1a.SetPlaceHolder("Password")
	lbl1 := widget.NewLabel("[0B 00000000] keyfile not selected")
	btn1 := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectKF(lbl1, &l.kf, l.mask) })
	ent1b := widget.NewEntry()
	ent1b.SetPlaceHolder("port/secret: 8001/...")
	btn1b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceiveKF(l.Window, lbl1, ent1b, &l.kf, l.mask) })
	box1 := container.NewBorder(nil, nil, container.NewHBox(btn1, btn1b), nil, ent1b)

	// part2: login
	loginBtn := widget.NewButton("Login", func() {
		if !l.fetched {
			dialog.ShowInformation("Error", "Search account first", l.Window)
			return
		}
		pw := Bencode.NormPW(ent1a.Text)
		ent1a.SetText("")
		var kf []byte
		if len(l.kf) > 0 {
			kf, _ = l.mask.XOR(l.kf)
		}

		go func() {
			defer sclear(pw)
			defer sclear(kf)
			pevfs, hkey, err := LoginAccFile(l.tmpPath, pw, kf)
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, l.Window) })
				return
			}
			os.Remove(l.tmpPath)
			l.tmpPath = ""
			vio, err := Config.GetIO(pevfs.Account.WriteAuth)
			if err != nil {
				sclear(hkey)
				fyne.Do(func() { dialog.ShowError(err, l.Window) })
				return
			}
			sched := new(Scheduler)
			sched.Init(pevfs, vio, l.msg, l.salt, hkey)
			fyne.Do(func() { l.switchToViewer(sched) })
		}()
	})
	loginBtn.Importance = widget.HighImportance

	// part3: create
	ent3a := widget.NewEntry()
	ent3a.SetPlaceHolder("Storage Name")
	ent3b := widget.NewEntry()
	ent3b.SetPlaceHolder("Public Message")
	ent3c := widget.NewEntry()
	ent3c.SetPlaceHolder("Server WrKey (Base64)")
	if Config.IsLocal {
		ent3c.SetText("No WrKey (Local Mode)")
		ent3c.Disable()
	}

	btn3 := widget.NewButton("Create", func() {
		storage := ent3a.Text
		msg := ent3b.Text
		if storage == "" {
			dialog.ShowInformation("Error", "Storage name cannot be empty", l.Window)
			return
		}
		pw := Bencode.NormPW(ent1a.Text)
		ent1a.SetText("")
		var kf []byte
		if len(l.kf) > 0 {
			kf, _ = l.mask.XOR(l.kf)
		}

		go func() {
			defer sclear(pw)
			defer sclear(kf)
			var wrkey []byte
			if Config.IsLocal {
				js, err := os.ReadFile(Config.LocalMeta)
				if err != nil {
					fyne.Do(func() { dialog.ShowError(err, l.Window) })
					return
				}
				meta := new(FalseCrypt.ChunkMeta)
				if err := meta.Init(string(js)); err != nil {
					fyne.Do(func() { dialog.ShowError(err, l.Window) })
					return
				}
				wrkey = meta.WriteKey
			} else {
				var err error
				wrkey, err = base64.StdEncoding.DecodeString(ent3c.Text)
				fyne.Do(func() { ent3c.SetText("") })
				if err != nil {
					fyne.Do(func() { dialog.ShowError(fmt.Errorf("invalid WriteKey base64: %v", err), l.Window) })
					return
				}
			}
			vio, err := Config.GetIO(wrkey)
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, l.Window) })
				return
			}
			if err := MakeAccFile(storage, msg, pw, kf, vio, wrkey); err != nil {
				fyne.Do(func() { dialog.ShowError(err, l.Window) })
				return
			}
			fyne.Do(func() { dialog.ShowInformation("Success", "Account created (root)", l.Window) })
		}()
	})
	btn3.Importance = widget.HighImportance

	// part4: assemble
	box4a := container.NewVBox(
		container.NewBorder(nil, nil, btn0, nil, ent0), lbl0,
		widget.NewSeparator(),
		ent1a, lbl1, box1,
		layout.NewSpacer(),
		loginBtn,
	)
	box4b := container.NewVBox(
		ent3a, ent3b, ent3c,
		layout.NewSpacer(),
		widget.NewLabel(FC_VERSION), btn3,
	)
	l.Window.SetContent(container.NewGridWithColumns(2, widget.NewCard("Unlock Existing", "기존 저장소 로그인", box4a), widget.NewCard("Create New", "새로운 저장소 생성", box4b)))
}

func (l *LoginPage) switchToViewer(sched *Scheduler) {
	v := new(ViewerPage)
	v.Main(l.App, sched)
	l.Window.Close()
}

// ===== viewer page =====
type ViewerPage struct {
	App    fyne.App
	Window fyne.Window
	Sched  *Scheduler
	mask   *Bencrypt.Masker

	Selected    map[string]bool
	MoveSources []string
	MoveSrcPath string
	IsMoveMode  bool

	// cached ls data
	Names   []string
	Sizes   []uint64
	EdTimes []uint64
	SecLvls []uint8
	Flags   [][]bool

	// widget refs
	contentBox  *fyne.Container
	toolbarBox  *fyne.Container
	gridWrap    *fyne.Container
	pathLabel   *widget.Label
	timerLabel  *widget.Label
	progressBar *widget.ProgressBar

	// pre-built tab contents
	viewerContent  fyne.CanvasObject
	debugContent   fyne.CanvasObject
	accountContent fyne.CanvasObject

	// debug entries & widgets
	ioLogEntry     *widget.Entry
	shellLogEntry  *widget.Entry
	debugInfoEntry *widget.Entry
	statusLabel    *widget.Label

	// expire timer
	ExpireAt time.Time
}

func (v *ViewerPage) Main(a fyne.App, sched *Scheduler) {
	v.App = a
	v.Sched = sched
	v.mask = Bencrypt.GetMasker(-1)
	v.Selected = make(map[string]bool)

	v.Window = v.App.NewWindow("FalseCrypt")
	v.Fill()
	v.Window.Resize(fyne.NewSize(1000*BaseUI.FyneSize, 600*BaseUI.FyneSize))
	v.Window.CenterOnScreen()

	// termination check
	v.Window.SetCloseIntercept(func() {
		isWorking := v.Sched != nil && v.Sched.IsWorking.Load()
		isUpdated := v.Sched != nil && v.Sched.IsUpdated
		if isWorking || isUpdated {
			dialog.ShowConfirm("Commit Warning",
				"Work in progress or unstored changes detected. Terminate anyway?",
				func(ok bool) {
					if ok {
						v.secureWipe()
						v.Window.Close()
					}
				}, v.Window)
			return
		}
		v.secureWipe()
		v.Window.Close()
	})

	v.startTimer()
	v.startPoller()
	v.Window.Show()
}

func (v *ViewerPage) Fill() {
	v.viewerContent = v.viewTab()
	v.debugContent = v.debugTab()
	v.accountContent = v.accTab()

	v.contentBox = container.NewStack(v.viewerContent)
	box0 := v.statusBar()
	v.Window.SetContent(container.NewBorder(nil, box0, nil, nil, v.contentBox))
}

// viewer helpers
func (v *ViewerPage) startTimer() {
	if Config.AutoExpire <= 0 {
		return
	}
	v.ExpireAt = time.Now().Add(time.Duration(Config.AutoExpire) * time.Minute)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if v.Sched == nil {
				return
			}
			// pause timer while working
			if v.Sched.IsWorking.Load() {
				v.ExpireAt = v.ExpireAt.Add(1 * time.Second)
				continue
			}
			remaining := time.Until(v.ExpireAt)
			if remaining <= 0 {
				v.secureWipe()
				fyne.Do(func() { v.App.Quit() })
				return
			}
			if v.timerLabel != nil {
				mins := int(remaining.Minutes())
				secs := int(remaining.Seconds()) % 60
				fyne.Do(func() { v.timerLabel.SetText(fmt.Sprintf("Expire in %02d:%02d", mins, secs)) })
			}
		}
	}()
}

func (v *ViewerPage) startPoller() {
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			if v.Sched == nil {
				return
			}
			if v.progressBar != nil {
				fyne.Do(func() { v.progressBar.SetValue(v.Sched.Log.GetPercent()) })
			}
		}
	}()
}

func (v *ViewerPage) secureWipe() {
	if v.Sched != nil {
		sclear(v.Sched.Hkey)
		v.Sched = nil
	}
}

func (v *ViewerPage) runAsync(op string, fn func()) {
	if v.Sched.IsWorking.Load() {
		dialog.ShowInformation("Already working", "Cannot start async operation: "+op, v.Window)
		return
	}
	go fn()
}

func (v *ViewerPage) showTab(tab string) {
	switch tab {
	case "viewer":
		v.contentBox.Objects = []fyne.CanvasObject{v.viewerContent}
	case "debug":
		v.contentBox.Objects = []fyne.CanvasObject{v.debugContent}
		v.refreshDebug()
	case "account":
		v.contentBox.Objects = []fyne.CanvasObject{v.accountContent}
	}
	v.contentBox.Refresh()
}

// ----- viewer tab -----
func (v *ViewerPage) viewTab() fyne.CanvasObject {
	v.toolbarBox = container.NewHBox()
	v.rebuild()
	box0 := v.navBar()
	box1 := container.NewVBox(container.NewHScroll(v.toolbarBox), widget.NewSeparator(), box0)
	v.gridWrap = container.NewGridWrap(fyne.NewSize(210, 110))
	box2 := container.NewVScroll(v.gridWrap)
	v.refresh()
	return container.NewBorder(box1, nil, nil, nil, box2)
}

func (v *ViewerPage) toolbar() []fyne.CanvasObject {
	// items list
	items := []fyne.CanvasObject{
		widget.NewButtonWithIcon("Import", theme.FileIcon(), func() { v.importFiles() }),
		widget.NewButtonWithIcon("Import", theme.FolderOpenIcon(), func() { v.importFolder() }),
		widget.NewButtonWithIcon("Export", theme.DownloadIcon(), func() { v.export() }),
		widget.NewButtonWithIcon("Mkdir", theme.FolderNewIcon(), func() { v.mkdir() }),
		widget.NewButtonWithIcon("Rename", theme.DocumentCreateIcon(), func() { v.rename() }),
		widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() { v.rm() }),
	}

	// move controls
	if v.IsMoveMode {
		btn0 := widget.NewButtonWithIcon("Move Here", theme.ConfirmIcon(), func() { v.mvFinish() })
		btn0.Importance = widget.WarningImportance
		btn1 := widget.NewButtonWithIcon("Cancel", theme.CancelIcon(), func() { v.mvCancel() })
		items = append(items, btn0, btn1)
	} else {
		btn0 := widget.NewButtonWithIcon("Move", theme.ContentCutIcon(), func() { v.mvStart() })
		items = append(items, btn0)
	}

	// system actions
	items = append(items,
		widget.NewButtonWithIcon("Chmod", theme.SettingsIcon(), func() { v.chmod() }),
		widget.NewButtonWithIcon("View", theme.InfoIcon(), func() { v.cat() }),
		widget.NewButtonWithIcon("Commit", theme.ConfirmIcon(), func() { v.commit() }),
		widget.NewButtonWithIcon("Sync", theme.ViewRefreshIcon(), func() { v.sync() }),
	)
	return items
}

func (v *ViewerPage) rebuild() {
	v.toolbarBox.Objects = v.toolbar()
	v.toolbarBox.Refresh()
}

func (v *ViewerPage) navBar() fyne.CanvasObject {
	v.pathLabel = widget.NewLabel("/")
	box0 := container.NewHBox(
		widget.NewButtonWithIcon("", theme.NavigateBackIcon(), func() { v.back() }),
		widget.NewButtonWithIcon("", theme.HomeIcon(), func() { v.root() }),
		widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), func() { v.refresh() }),
		widget.NewButton("Select All", func() { v.selectAll() }),
	)
	return container.NewBorder(nil, nil, box0, nil, v.pathLabel)
}

// ----- grid -----
func (v *ViewerPage) refresh() {
	v.Names, v.Sizes, v.EdTimes, v.SecLvls, v.Flags = v.Sched.Ls()
	v.Selected = make(map[string]bool)
	v.rebuildGrid()
	v.updatePath()
}

func (v *ViewerPage) rebuildGrid() {
	cards := make([]fyne.CanvasObject, len(v.Names))
	for i := range v.Names {
		cards[i] = v.gridCard(i)
	}
	v.gridWrap.Objects = cards
	v.gridWrap.Refresh()
}

func (v *ViewerPage) updatePath() {
	v.pathLabel.SetText(strings.Join(v.Sched.CwdPath, "/") + "/")
}

func (v *ViewerPage) gridCard(idx int) fyne.CanvasObject {
	name := v.Names[idx]
	isDir := v.Flags[idx][0]
	userA := v.Flags[idx][1]
	userB := v.Flags[idx][2]
	isSelected := v.Selected[name]

	// background
	bgColor := color.NRGBA{R: 40, G: 42, B: 48, A: 255} // gray
	if isSelected {
		bgColor = color.NRGBA{R: 50, G: 80, B: 130, A: 255} // dark blue
	}
	bg := canvas.NewRectangle(bgColor)
	bg.CornerRadius = 6

	// icon
	iconRes := getFileIcon(name, isDir)
	iconImg := canvas.NewImageFromResource(iconRes)
	iconImg.FillMode = canvas.ImageFillContain
	iconImg.SetMinSize(fyne.NewSize(48, 48))

	// name (wrap at 18 display-width units: ASCII=1, others=2)
	wrapped := wrapName(name, 18)
	nameLines := strings.Split(wrapped, "\n")
	var nameObjs []fyne.CanvasObject
	for _, ln := range nameLines {
		t := canvas.NewText(ln, color.NRGBA{R: 245, G: 245, B: 245, A: 255})
		t.TextStyle.Bold = true
		t.TextSize = 14
		nameObjs = append(nameObjs, t)
	}
	nameBox := container.NewVBox(nameObjs...)

	// size, time
	sizeStr := formatSize(v.Sizes[idx])
	timeStr := formatTime(v.EdTimes[idx])
	infoText := canvas.NewText(" |  "+sizeStr+"  |  "+timeStr, color.NRGBA{R: 190, G: 190, B: 190, A: 255}) // bright gray
	infoText.TextSize = 11

	// secure level
	sl := v.SecLvls[idx]
	slText := canvas.NewText(slName(sl, false), slColor(sl))
	slText.TextStyle.Bold = true
	slText.TextSize = 11

	// user bits
	var tags []string
	if userA {
		tags = append(tags, v.Sched.FS.Account.UserBitA)
	}
	if userB {
		tags = append(tags, v.Sched.FS.Account.UserBitB)
	}
	tagStr := strings.Join(tags, " ")
	tagText := canvas.NewText(tagStr, color.NRGBA{R: 140, G: 220, B: 140, A: 255}) // green
	tagText.TextSize = 11

	// tap handlers
	onTap := func() {
		if v.Selected[name] {
			delete(v.Selected, name)
			bg.FillColor = color.NRGBA{R: 40, G: 42, B: 48, A: 255} // gray
		} else {
			v.Selected[name] = true
			bg.FillColor = color.NRGBA{R: 50, G: 80, B: 130, A: 255} // dark blue
		}
		bg.Refresh()
	}
	onDblTap := func() {
		if isDir {
			v.Sched.Cd(name, true)
			v.refresh()
		}
	}

	// join to card
	content := container.NewVBox(
		container.NewHBox(iconImg, nameBox),
		container.NewHBox(slText, infoText),
		tagText,
	)
	card := new(fileCard)
	card.Init(bg, content, onTap, onDblTap)
	card.ExtendBaseWidget(card)
	return card
}

func (v *ViewerPage) selected() []string {
	var names []string
	for name := range v.Selected {
		names = append(names, name)
	}
	return names
}

// ----- status bar -----
func (v *ViewerPage) statusBar() fyne.CanvasObject {
	v.timerLabel = widget.NewLabel("Expire in --:--")
	btn0 := widget.NewButton("Extend", func() {
		if Config.AutoExpire > 0 {
			v.ExpireAt = time.Now().Add(time.Duration(Config.AutoExpire) * time.Minute)
		}
	})
	box0a := container.NewHBox(
		widget.NewButton("Viewer", func() { v.showTab("viewer") }),
		widget.NewButton("Debug", func() { v.showTab("debug") }),
		widget.NewButton("Account", func() { v.showTab("account") }),
	)
	box0b := container.NewHBox(
		widget.NewLabel(fmt.Sprintf("%s@%s | %s", v.Sched.FS.Account.UserName, v.Sched.FS.Account.StorageName, slName(v.Sched.FS.Account.SecureLevel, true))),
		v.timerLabel, btn0,
	)
	return container.NewBorder(nil, nil, box0a, box0b, layout.NewSpacer())
}

// ----- debug tab -----
func (v *ViewerPage) debugTab() fyne.CanvasObject {
	// part0: fields init
	v.ioLogEntry = widget.NewMultiLineEntry()
	v.ioLogEntry.Wrapping = fyne.TextWrapWord
	v.shellLogEntry = widget.NewMultiLineEntry()
	v.shellLogEntry.Wrapping = fyne.TextWrapWord
	v.debugInfoEntry = widget.NewMultiLineEntry()
	v.debugInfoEntry.Wrapping = fyne.TextWrapWord
	v.statusLabel = widget.NewLabel("Status: IDLE")
	v.progressBar = widget.NewProgressBar()

	// part1: top bar
	btn1a := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), func() {
		v.refreshDebug()
	})
	btn1b := widget.NewButtonWithIcon("Clear", theme.DeleteIcon(), func() {
		v.Sched.Log.GetLog(true)
		v.ioLogEntry.SetText("")
		v.shellLogEntry.SetText("")
		v.debugInfoEntry.SetText("")
	})
	box1 := container.NewVBox(
		v.progressBar,
		container.NewHBox(btn1a, btn1b, v.statusLabel),
	)

	// part2: columns
	btn2a := widget.NewButtonWithIcon("Debug", theme.InfoIcon(), v.lsDbg)
	btn2b := widget.NewButtonWithIcon("Search", theme.SearchIcon(), v.schDialog)
	box2a := container.NewBorder(widget.NewLabel("IO Log"), nil, nil, nil, v.ioLogEntry)
	box2b := container.NewBorder(widget.NewLabel("Shell Log"), nil, nil, nil, v.shellLogEntry)
	box2c := container.NewBorder(
		container.NewHBox(widget.NewLabel("Debug Info"), btn2a, btn2b),
		nil, nil, nil, v.debugInfoEntry,
	)

	// part3: assemble
	split0 := container.NewHSplit(box2a, box2b)
	split0.Offset = 0.5
	split1 := container.NewHSplit(split0, box2c)
	split1.Offset = 0.66
	return container.NewBorder(box1, nil, nil, nil, split1)
}

func (v *ViewerPage) lsDbg() {
	v.debugInfoEntry.SetText("LsDbg analyzing...")
	var tgt string
	for name := range v.Selected {
		tgt = name
		break
	}
	tgtName := strings.Join(v.Sched.CwdPath, "/") + "/" + tgt

	go func() {
		uid, key, size, esize, fnum, dnum := v.Sched.LsDbg(tgt)
		info := fmt.Sprintf("Target: %s\nUID: %d\nKey: %s\nTotal Size: %s\n(%d B)\nEncrypted Size: %s\n(%d B)\nFiles: %d\nDirs: %d",
			tgtName, uid, hex.EncodeToString(key), formatSize(size), size, formatSize(esize), esize, fnum, dnum)
		sclear(key)
		fyne.Do(func() { v.debugInfoEntry.SetText(info) })
	}()
}

func (v *ViewerPage) schDialog() {
	// part0: condition set
	ent0 := widget.NewEntry()
	ent0.SetPlaceHolder("Regex Pattern")
	chk0a := widget.NewCheck(v.Sched.FS.Account.UserBitA, nil)
	chk0b := widget.NewCheck(v.Sched.FS.Account.UserBitB, nil)
	sel0 := widget.NewSelect([]string{"CONTROLLED", "CONFIDENTIAL", "SECRET", "TOP SECRET"}, nil)
	sel0.SetSelected("CONTROLLED")

	// part1: form
	form1 := dialog.NewForm("Search Settings", "Search", "Cancel", []*widget.FormItem{
		widget.NewFormItem("Pattern", ent0),
		widget.NewFormItem("Flag A", chk0a),
		widget.NewFormItem("Flag B", chk0b),
		widget.NewFormItem("Security Level", sel0),
	}, func(b bool) {
		if !b {
			return
		}
		go func() {
			res := v.Sched.Search(ent0.Text, chk0a.Checked, chk0b.Checked, parseSL(sel0.Selected))
			fyne.Do(func() {
				if len(res) == 0 {
					v.debugInfoEntry.SetText("No results found.")
				} else {
					v.debugInfoEntry.SetText(strings.Join(res, "\n"))
				}
			})
		}()
	}, v.Window)
	form1.Resize(fyne.NewSize(400, 250))
	form1.Show()
}

func (v *ViewerPage) refreshDebug() {
	// update IO log
	go func() {
		if v.Sched.IsReadonly {
			fyne.Do(func() { v.ioLogEntry.SetText("Cannot fetch remote log while readonly") })
		} else {
			log, err := v.Sched.Vio.GetLog()
			if err == nil {
				fyne.Do(func() { v.ioLogEntry.SetText(v.ioLogEntry.Text + "\n" + log) })
			} else {
				fyne.Do(func() { v.ioLogEntry.SetText("Failed to collect IO logs: " + err.Error()) })
			}
		}
	}()

	// update shell log
	v.shellLogEntry.SetText(v.Sched.Log.GetLog(false))

	// update flags
	info := "Status:"
	isWorking := v.Sched.IsWorking.Load()
	if isWorking {
		info += " WORKING"
	}
	isUpdated := v.Sched.IsUpdated
	if isUpdated {
		info += " UPDATED"
	}
	if !isWorking && !isUpdated {
		info += " IDLE"
	}
	v.statusLabel.SetText(info)
}

// ----- account tab -----
func (v *ViewerPage) accTab() fyne.CanvasObject {
	// part0: shared inputs
	ent0a := widget.NewEntry()
	ent0a.SetPlaceHolder("Public Message")
	ent0b := widget.NewPasswordEntry()
	ent0b.SetPlaceHolder("Password")

	var kfData []byte
	lbl0 := widget.NewLabel("[0B 00000000] keyfile not selected")
	btn0a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() {
		BaseUI.SelectKF(lbl0, &kfData, v.mask)
	})
	ent0c := widget.NewEntry()
	ent0c.SetPlaceHolder("port/secret: 8001/...")
	btn0b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() {
		BaseUI.ReceiveKF(v.Window, lbl0, ent0c, &kfData, v.mask)
	})
	box0 := container.NewBorder(nil, nil, container.NewHBox(btn0a, btn0b), nil, ent0c)

	// part1: password change
	ent1 := widget.NewEntry()
	ent1.SetPlaceHolder("New WrKey (Optional, Base64)")
	btn1 := widget.NewButton("Change Password", func() {
		msg := ent0a.Text
		pw := []byte(ent0b.Text)
		ent0b.SetText("")
		var kf []byte
		if len(kfData) > 0 {
			kf, _ = v.mask.XOR(kfData)
		}
		var wrkey []byte
		if ent1.Text != "" {
			var err error
			wrkey, err = base64.StdEncoding.DecodeString(ent1.Text)
			ent1.SetText("")
			if err != nil {
				dialog.ShowError(fmt.Errorf("invalid WrKey: %v", err), v.Window)
				sclear(pw)
				sclear(kf)
				return
			}
		}
		v.runAsync("passwd", func() {
			v.Sched.Passwd(msg, pw, kf, wrkey)
			sclear(pw)
			sclear(kf)
			sclear(wrkey)
		})
	})
	btn1.Importance = widget.DangerImportance

	// part2: share account
	ent2 := widget.NewEntry()
	ent2.SetPlaceHolder("Target Username")

	sel2 := widget.NewSelect([]string{"TOP SECRET", "SECRET", "CONFIDENTIAL", "CONTROLLED"}, nil)
	sel2.SetSelected("CONTROLLED")

	btn2 := widget.NewButton("Create Share Account", func() {
		username := ent2.Text
		msg := ent0a.Text
		if username == "" {
			dialog.ShowInformation("Error", "Enter target username", v.Window)
			return
		}
		sl := parseSL(sel2.Selected)
		pw := []byte(ent0b.Text)
		ent0b.SetText("")
		var kf []byte
		if len(kfData) > 0 {
			kf, _ = v.mask.XOR(kfData)
		}
		v.runAsync("share", func() {
			v.Sched.Share(username, sl, msg, pw, kf)
			sclear(pw)
			sclear(kf)
		})
	})
	btn2.Importance = widget.HighImportance

	// part3: user flag change
	ent3a := widget.NewEntry()
	ent3a.SetText(v.Sched.FS.Account.UserBitA)
	ent3a.SetPlaceHolder("User Flag A")

	ent3b := widget.NewEntry()
	ent3b.SetText(v.Sched.FS.Account.UserBitB)
	ent3b.SetPlaceHolder("User Flag B")

	btn3 := widget.NewButton("Change Flags", func() {
		userA := ent3a.Text
		userB := ent3b.Text
		v.runAsync("chflag", func() {
			v.Sched.Chflag(userA, userB)
		})
	})
	btn3.Importance = widget.HighImportance

	lbl3a := widget.NewLabel("Flag A: ")
	lbl3b := widget.NewLabel("Flag B: ")
	box3a := container.NewBorder(nil, nil, lbl3a, nil, ent3a)
	box3b := container.NewBorder(nil, nil, lbl3b, nil, ent3b)

	// part4: assemble
	card0 := widget.NewCard("Shared Credentials", "", container.NewVBox(
		ent0a, ent0b,
		lbl0,
		box0,
	))
	card1 := widget.NewCard("Operations", "", container.NewVBox(
		ent1,
		btn1,
		widget.NewSeparator(),
		ent2,
		sel2,
		btn2,
		widget.NewSeparator(),
		box3a,
		box3b,
		btn3,
	))
	return container.NewGridWithColumns(2, card0, card1)
}

// ----- navigation handlers -----
func (v *ViewerPage) back() {
	cwdPath := v.Sched.CwdPath
	if len(cwdPath) <= 1 {
		return
	}
	parentParts := cwdPath[1 : len(cwdPath)-1]
	if len(parentParts) == 0 {
		v.root()
		return
	}
	v.Sched.Cd(strings.Join(parentParts, "/"), false)
	v.refresh()
}

func (v *ViewerPage) root() {
	s := v.Sched
	s.lock.Lock()
	s.Cwd = &s.FS.Root
	s.CwdPath = []string{s.FS.Meta[s.FS.Root.GetUID()].Name}
	s.lock.Unlock()
	v.refresh()
}

func (v *ViewerPage) selectAll() {
	if len(v.Selected) == len(v.Names) {
		v.Selected = make(map[string]bool)
	} else {
		for _, name := range v.Names {
			v.Selected[name] = true
		}
	}
	v.rebuildGrid()
}

// ----- operation handlers -----
func (v *ViewerPage) importFiles() {
	files, err := BaseUI.ZenityMultiFiles("Select Files to Import")
	if err != nil || len(files) == 0 {
		return
	}
	v.runAsync("import", func() {
		v.Sched.Import(files)
		fyne.Do(func() { v.refresh() })
	})
}

func (v *ViewerPage) importFolder() {
	folder, err := BaseUI.ZenityFolder("Select Folder to Import")
	if err != nil || folder == "" {
		return
	}
	v.runAsync("import", func() {
		v.Sched.Import([]string{folder})
		fyne.Do(func() { v.refresh() })
	})
}

func (v *ViewerPage) export() {
	sels := v.selected()
	if len(sels) == 0 {
		dialog.ShowInformation("Notice", "Select items to export", v.Window)
		return
	}
	dialog.ShowConfirm("Export Confirmation",
		fmt.Sprintf("Export %d item(s) to local storage?", len(sels)),
		func(ok bool) {
			if !ok {
				return
			}
			dst, err := BaseUI.ZenityFolder("Select Destination Folder")
			if err != nil || dst == "" {
				return
			}
			v.runAsync("export", func() {
				v.Sched.Export(sels, dst)
			})
		}, v.Window)
}

func (v *ViewerPage) mkdir() {
	ent0 := widget.NewEntry()
	ent0.SetPlaceHolder("Folder Name")
	items := []*widget.FormItem{widget.NewFormItem("Name", ent0)}
	dialog.ShowForm("New Folder", "Create", "Cancel", items, func(ok bool) {
		if ok && ent0.Text != "" {
			v.Sched.Mkdir(ent0.Text)
			v.refresh()
		}
	}, v.Window)
}

func (v *ViewerPage) rename() {
	sels := v.selected()
	if len(sels) != 1 {
		dialog.ShowInformation("Notice", "Select 1 item to rename", v.Window)
		return
	}
	ent0 := widget.NewEntry()
	ent0.SetText(sels[0])
	items := []*widget.FormItem{widget.NewFormItem("Name", ent0)}
	dialog.ShowForm("Rename", "Rename", "Cancel", items, func(ok bool) {
		if ok && ent0.Text != "" {
			v.Sched.Rename(sels[0], ent0.Text)
			v.refresh()
		}
	}, v.Window)
}

func (v *ViewerPage) rm() {
	sels := v.selected()
	if len(sels) == 0 {
		dialog.ShowInformation("Notice", "Select items to delete", v.Window)
		return
	}
	dialog.ShowConfirm("Delete Confirmation",
		fmt.Sprintf("Delete %d item(s)?", len(sels)),
		func(ok bool) {
			if ok {
				v.runAsync("rm", func() {
					v.Sched.Rm(sels)
					fyne.Do(func() { v.refresh() })
				})
			}
		}, v.Window)
}

func (v *ViewerPage) mvStart() {
	sels := v.selected()
	if len(sels) == 0 {
		dialog.ShowInformation("Notice", "Select items to move", v.Window)
		return
	}
	v.MoveSources = sels
	var srcPath string
	if len(v.Sched.CwdPath) > 1 {
		srcPath = strings.Join(v.Sched.CwdPath[1:], "/")
	} else {
		srcPath = ""
	}
	v.MoveSrcPath = srcPath
	v.IsMoveMode = true
	v.Selected = make(map[string]bool)
	v.rebuild()
	v.rebuildGrid()
}

func (v *ViewerPage) mvFinish() {
	v.Sched.Mv(v.MoveSrcPath, v.MoveSources)
	v.IsMoveMode = false
	v.MoveSources = nil
	v.MoveSrcPath = ""
	v.rebuild()
	v.refresh()
}

func (v *ViewerPage) mvCancel() {
	v.IsMoveMode = false
	v.MoveSources = nil
	v.MoveSrcPath = ""
	v.rebuild()
	v.rebuildGrid()
}

func (v *ViewerPage) chmod() {
	// part0: validation
	sels := v.selected()
	if len(sels) != 1 {
		dialog.ShowInformation("Notice", "Select 1 item to chmod", v.Window)
		return
	}

	// part1: read current
	idx := -1
	for i, name := range v.Names {
		if name == sels[0] {
			idx = i
			break
		}
	}
	if idx == -1 {
		return
	}
	currUserA := v.Flags[idx][1]
	currUserB := v.Flags[idx][2]
	currSl := v.SecLvls[idx]

	// part2: form components
	chk0 := widget.NewCheck(v.Sched.FS.Account.UserBitA, nil)
	chk0.SetChecked(currUserA)
	chk1 := widget.NewCheck(v.Sched.FS.Account.UserBitB, nil)
	chk1.SetChecked(currUserB)
	chk2 := widget.NewCheck("Recursive", nil)
	sel0 := widget.NewSelect([]string{"TOP SECRET", "SECRET", "CONFIDENTIAL", "CONTROLLED"}, nil)
	sel0.SetSelected(slName(currSl, true))

	// part3: show form
	items := []*widget.FormItem{
		widget.NewFormItem("Flag A", chk0),
		widget.NewFormItem("Flag B", chk1),
		widget.NewFormItem("Security Level", sel0),
		widget.NewFormItem("Recursive", chk2),
	}
	dialog.ShowForm("Chmod", "Change", "Cancel", items, func(ok bool) {
		if ok {
			v.Sched.Chmod(sels[0], chk0.Checked, chk1.Checked, parseSL(sel0.Selected), chk2.Checked)
			v.refresh()
		}
	}, v.Window)
}

func (v *ViewerPage) cat() {
	sels := v.selected()
	if len(sels) == 0 {
		dialog.ShowInformation("Notice", "Select file to view", v.Window)
		return
	}
	save := func(nm string, d []byte) {
		dst, err := BaseUI.ZenityFolder("Select directory to save")
		if err == nil {
			os.WriteFile(filepath.Join(dst, nm), d, 0644)
		}
	}
	v.runAsync("cat", func() {
		contents := v.Sched.Cat(sels)
		dataMap := make(map[string][]byte)
		for i, name := range sels {
			if i < len(contents) && contents[i] != nil {
				dataMap[name] = contents[i]
			}
		}
		if len(dataMap) == 0 {
			return
		}
		fyne.Do(func() {
			var mv MemView.MemView
			mv.Main(v.App, "InMem Viewer", dataMap, save, false, true, -1)
		})
	})
}

func (v *ViewerPage) commit() {
	v.runAsync("commit", func() {
		v.Sched.Commit()
	})
}

func (v *ViewerPage) sync() {
	dialog.ShowConfirm("Sync Confirmation",
		"Start remote synchronization?",
		func(ok bool) {
			if ok {
				v.runAsync("sync", func() {
					v.Sched.Sync()
				})
			}
		}, v.Window)
}

// ===== entry point =====
func main() {
	defer func() {
		if r := recover(); r != nil {
			os.WriteFile("panic-log.txt", []byte(fmt.Sprintf("panic while main.main: %v", r)), 0644)
		}
	}()
	if err := Config.Load(); err != nil {
		panic(err) // exit directly
	}
	var p LoginPage
	p.Main()
}
