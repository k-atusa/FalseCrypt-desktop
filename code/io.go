// test826c : project USAG FalseCrypt-desktop
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
)

// ===== Remote Chunk IO =====
type ClientIO struct {
	serverURL string
	wrkey     []byte
	mask      *Bencrypt.Masker
	client    *http.Client
}

func (c *ClientIO) Init(ip string, wrkey []byte) {
	if !strings.HasPrefix(ip, "http://") && !strings.HasPrefix(ip, "https://") {
		ip = "http://" + ip
	}
	c.serverURL = strings.TrimSuffix(ip, "/")
	c.mask = Bencrypt.GetMasker(-1)
	c.wrkey, _ = c.mask.XOR(wrkey)
	c.client = &http.Client{
		Timeout: 60 * time.Second,
	}
}

// HMAC-SHA3-256 [order][time][data]
func (c *ClientIO) makeAuth(order string, timestamp int64, value []byte) string {
	buf := make([]byte, len(order)+8+len(value))
	copy(buf[:len(order)], order)
	binary.LittleEndian.PutUint64(buf[len(order):len(order)+8], uint64(timestamp))
	copy(buf[len(order)+8:], value)
	wk, _ := c.mask.XOR(c.wrkey)
	defer sclear(wk)
	return hex.EncodeToString(Bencrypt.HMAC3256(wk, buf))
}

func (c *ClientIO) GetAccount(username string, dst io.Writer) error {
	var err error
	for i := 0; i < 3; i++ {
		err = func() error {
			// Get account data from server
			u := fmt.Sprintf("%s/api/fc/getaccount?username=%s", c.serverURL, url.QueryEscape(username))
			resp, e := c.client.Get(u)
			if e != nil {
				return e
			}
			defer resp.Body.Close()

			// Handle server errors, copy to dst
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
			}
			if s, ok := dst.(io.Seeker); ok {
				s.Seek(0, io.SeekStart)
			}
			if t, ok := dst.(interface{ Truncate(size int64) error }); ok {
				t.Truncate(0)
			}
			_, e = io.Copy(dst, resp.Body)
			return e
		}()
		if err == nil {
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return err
}

func (c *ClientIO) SetAccount(username string, src io.Reader, size int64) error {
	// Read account data from src
	data, err := io.ReadAll(io.LimitReader(src, size))
	if err != nil {
		return err
	}

	for i := 0; i < 3; i++ {
		err = func() error {
			chksumBytes := Bencrypt.SHA3256(data)
			chksum := hex.EncodeToString(chksumBytes)
			timestamp := time.Now().Unix()
			auth := c.makeAuth("SetAccount", timestamp, chksumBytes)

			// Upload account data to server
			u := fmt.Sprintf("%s/api/fc/setaccount?username=%s&timestamp=%d&auth=%s&chksum=%s",
				c.serverURL, url.QueryEscape(username), timestamp, auth, chksum)

			resp, e := c.client.Post(u, "application/octet-stream", bytes.NewReader(data))
			if e != nil {
				return e
			}
			defer resp.Body.Close()

			// Handle server errors
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
			}
			return nil
		}()
		if err == nil {
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return err
}

func (c *ClientIO) ReadChunk(cid []byte) ([]byte, error) {
	var data []byte
	var err error
	for i := 0; i < 3; i++ {
		data, err = func() ([]byte, error) {
			// Get chunk data from server
			u := fmt.Sprintf("%s/api/fc/readchunk?cid=%s", c.serverURL, hex.EncodeToString(cid))
			resp, e := c.client.Get(u)
			if e != nil {
				return nil, e
			}
			defer resp.Body.Close()

			// Handle server errors
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
			}
			return io.ReadAll(resp.Body)
		}()
		if err == nil {
			return data, nil
		}
		time.Sleep(3 * time.Second)
	}
	return nil, err
}

func (c *ClientIO) WriteChunk(cid []byte, data []byte) error {
	var err error
	for i := 0; i < 3; i++ {
		err = func() error {
			// Calculate checksum and timestamp
			chksumBytes := Bencrypt.SHA3256(data)
			chksum := hex.EncodeToString(chksumBytes)
			timestamp := time.Now().Unix()
			auth := c.makeAuth("WriteChunk", timestamp, chksumBytes)

			// Upload chunk data to server
			u := fmt.Sprintf("%s/api/fc/writechunk?cid=%s&timestamp=%d&auth=%s&chksum=%s", c.serverURL, hex.EncodeToString(cid), timestamp, auth, chksum)
			resp, e := c.client.Post(u, "application/octet-stream", bytes.NewReader(data))
			if e != nil {
				return e
			}
			defer resp.Body.Close()

			// Handle server errors
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
			}
			return nil
		}()
		if err == nil {
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return err
}

func (c *ClientIO) DelChunk(cid []byte) error {
	// Calculate checksum and timestamp
	timestamp := time.Now().Unix()
	auth := c.makeAuth("DelChunk", timestamp, cid)

	// Request chunk deletion on server
	u := fmt.Sprintf("%s/api/fc/delchunk?cid=%s&timestamp=%d&auth=%s", c.serverURL, hex.EncodeToString(cid), timestamp, auth)
	resp, err := c.client.Post(u, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Handle server errors
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

func (c *ClientIO) GetLog() (string, error) {
	// request server log
	timestamp := time.Now().Unix()
	auth := c.makeAuth("GetLog", timestamp, nil)
	u := fmt.Sprintf("%s/api/fc/getlog?timestamp=%d&auth=%s", c.serverURL, timestamp, auth)
	resp, err := c.client.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Handle server errors
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (c *ClientIO) CheckChunk() []byte {
	// request bloom filter from server
	timestamp := time.Now().Unix()
	auth := c.makeAuth("CheckChunk", timestamp, nil)
	u := fmt.Sprintf("%s/api/fc/checkchunk?timestamp=%d&auth=%s", c.serverURL, timestamp, auth)
	resp, err := c.client.Get(u)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Handle server errors
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return data
}

func (c *ClientIO) TrimChunk(bloom []byte) error {
	// Calculate checksum and timestamp
	chksumBytes := Bencrypt.SHA3256(bloom)
	chksum := hex.EncodeToString(chksumBytes)
	timestamp := time.Now().Unix()
	auth := c.makeAuth("TrimChunk", timestamp, chksumBytes)

	// Send bloom filter to server
	u := fmt.Sprintf("%s/api/fc/trimchunk?timestamp=%d&auth=%s&chksum=%s", c.serverURL, timestamp, auth, chksum)
	resp, err := c.client.Post(u, "application/octet-stream", bytes.NewReader(bloom))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

func (c *ClientIO) TrimEmpty() error {
	// Calculate checksum and timestamp
	timestamp := time.Now().Unix()
	auth := c.makeAuth("TrimEmpty", timestamp, nil)

	// Request chunk deletion on server
	u := fmt.Sprintf("%s/api/fc/trimempty?timestamp=%d&auth=%s", c.serverURL, timestamp, auth)
	resp, err := c.client.Post(u, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}
